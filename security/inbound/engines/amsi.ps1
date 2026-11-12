# ============================================================
# OTLC Guardian - inbound-file check 8: the AMSI engine
# // onthelevelconcepts.com
# Version: 1.5.0
# ============================================================
#
# Hands one file, and the archive entries Guardian read out of it,
# to the antivirus registered as this machine's AMSI provider
# (Antimalware Scan Interface). Started by
# security/inbound/checks/antivirus.js as
#
#   powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File amsi.ps1
#
# It is a plain script file on purpose: an antivirus can read it, and
# a command line with encoded script text in it is what behaviour
# shields flag.
#
# Input, all of it untrusted and none of it ever run:
#   GUARDIAN_AMSI_FILE     path of the file on disk
#   GUARDIAN_AMSI_NAME     its name, given to the provider as the content name
#   GUARDIAN_AMSI_CHUNK    bytes handed to one AmsiScanBuffer call
#   GUARDIAN_AMSI_OVERLAP  bytes of the last chunk repeated at the start of the next
#   standard input         the archive entries, one frame each, until end of input:
#                            4 bytes   length of the name (little endian)
#                            n bytes   the entry's inner path, UTF-8
#                            8 bytes   length of the data (little endian)
#                            n bytes   the entry's bytes
#
# Output: one line of JSON. This script decides nothing; antivirus.js
# reads the numbers.
#   providers      path of each registered provider DLL (its class id when the path is not found)
#   products       what Windows Security Center lists: name, state (productState), paths
#   productsError  why Security Center could not be read, or null
#   init           HRESULT of AmsiInitialize
#   session        HRESULT of AmsiOpenSession
#   result         highest AMSI_RESULT over the file's chunks
#   hr             first failing HRESULT of AmsiScanBuffer on the file
#   chunks         AmsiScanBuffer calls made on the file
#   entries        archive entries read from standard input
#   flagged        entries whose result is not clean: index (order of arrival) and result
#   entryErrors    entries whose scan call failed: index and hr
#   error          a .NET or PowerShell failure (the file could not be opened, a frame was cut short)
#
# Everything is scanned in one AMSI session. Nothing is written to
# disk, no antivirus setting is read for change or changed, and no
# network is used.
# ============================================================

$ErrorActionPreference = 'Stop'
$out = @{
  providers = @(); products = @(); productsError = $null
  init = $null; session = $null; result = $null; hr = 0; chunks = 0
  entries = 0; flagged = @(); entryErrors = @(); error = $null
}

# Fills $buffer[$offset .. $offset + $count - 1] from $stream. False when the stream ends first.
function Read-Exact($stream, [byte[]]$buffer, [int]$offset, [int]$count) {
  $done = 0
  while ($done -lt $count) {
    $read = $stream.Read($buffer, $offset + $done, $count - $done)
    if ($read -le 0) { return $false }
    $done += $read
  }
  return $true
}

# Scans $length bytes of $stream under $name, in chunks that overlap so
# nothing is cut in two unseen. Always reads all $length bytes, so the
# next frame on standard input starts where it should. Returns the
# highest result, the first failing HRESULT and the number of calls.
function Scan-Stream($stream, [long]$length, [string]$name) {
  $answer = @{ result = 0; hr = 0; chunks = 0 }
  $carry = 0
  $remaining = $length
  $scanning = $true
  while ($remaining -gt 0) {
    $want = [int][Math]::Min([long]($script:buffer.Length - $carry), $remaining)
    if (-not (Read-Exact $stream $script:buffer $carry $want)) { throw "the data of $name ended early" }
    $remaining -= $want
    $filled = $carry + $want
    if ($scanning) {
      $verdict = 0
      $hr = [GuardianAmsi]::AmsiScanBuffer($script:context, $script:buffer, [uint32]$filled, $name, $script:session, [ref]$verdict)
      $answer.chunks += 1
      if ($hr -ne 0) { $answer.hr = $hr; $scanning = $false }
      else {
        if ($verdict -gt $answer.result) { $answer.result = $verdict }
        if ($verdict -ge 32768) { $scanning = $false }
      }
    }
    if ($remaining -gt 0) {
      $carry = [Math]::Min($script:overlap, $filled)
      [Array]::Copy($script:buffer, $filled - $carry, $script:buffer, 0, $carry)
    }
  }
  return $answer
}

try {
  $ids = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers' -ErrorAction SilentlyContinue | ForEach-Object { $_.PSChildName })
  foreach ($id in $ids) {
    $dll = (Get-ItemProperty ('HKLM:\SOFTWARE\Classes\CLSID\' + $id + '\InprocServer32') -ErrorAction SilentlyContinue).'(default)'
    if ($dll) { $out.providers += [Environment]::ExpandEnvironmentVariables($dll.Trim('"')) } else { $out.providers += $id }
  }

  # Whether the product behind the provider is switched on is Security
  # Center's to say. A provider whose product is off answers "clean"
  # to everything.
  try {
    foreach ($product in @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName 'AntiVirusProduct')) {
      $paths = @()
      foreach ($p in @($product.pathToSignedProductExe, $product.pathToSignedReportingExe)) {
        if ($p) { $paths += [Environment]::ExpandEnvironmentVariables([string]$p) }
      }
      $out.products += @{ name = [string]$product.displayName; state = [long]$product.productState; paths = $paths }
    }
  } catch {
    $out.productsError = $_.Exception.Message
  }

  if ($out.providers.Count -gt 0) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class GuardianAmsi {
  [DllImport("amsi.dll", CharSet = CharSet.Unicode)] public static extern int AmsiInitialize(string appName, out IntPtr context);
  [DllImport("amsi.dll")] public static extern int AmsiOpenSession(IntPtr context, out IntPtr session);
  [DllImport("amsi.dll", CharSet = CharSet.Unicode)] public static extern int AmsiScanBuffer(IntPtr context, byte[] buffer, uint length, string contentName, IntPtr session, out int result);
  [DllImport("amsi.dll")] public static extern void AmsiCloseSession(IntPtr context, IntPtr session);
  [DllImport("amsi.dll")] public static extern void AmsiUninitialize(IntPtr context);
}
"@
    $script:overlap = [int]$env:GUARDIAN_AMSI_OVERLAP
    $script:buffer = New-Object byte[] ([int]$env:GUARDIAN_AMSI_CHUNK)
    $script:context = [IntPtr]::Zero
    $out.init = [GuardianAmsi]::AmsiInitialize('OTLC Guardian inbound-check', [ref]$script:context)
    if ($out.init -eq 0) {
      try {
        $script:session = [IntPtr]::Zero
        $out.session = [GuardianAmsi]::AmsiOpenSession($script:context, [ref]$script:session)
        if ($out.session -eq 0) {
          try {
            # The file, read where it sits.
            $file = [IO.File]::Open($env:GUARDIAN_AMSI_FILE, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
            try {
              $answer = Scan-Stream $file $file.Length $env:GUARDIAN_AMSI_NAME
              $out.result = $answer.result
              $out.hr = $answer.hr
              $out.chunks = $answer.chunks
            } finally { $file.Dispose() }

            # The archive entries, each under its inner path.
            $stdin = [Console]::OpenStandardInput()
            $head = New-Object byte[] 8
            while (Read-Exact $stdin $head 0 4) {
              $nameBytes = New-Object byte[] ([BitConverter]::ToInt32($head, 0))
              if (-not (Read-Exact $stdin $nameBytes 0 $nameBytes.Length)) { throw 'an entry name ended early' }
              if (-not (Read-Exact $stdin $head 0 8)) { throw 'an entry length ended early' }
              $answer = Scan-Stream $stdin ([BitConverter]::ToInt64($head, 0)) ([Text.Encoding]::UTF8.GetString($nameBytes))
              if ($answer.hr -ne 0) { $out.entryErrors += @{ index = $out.entries; hr = $answer.hr } }
              elseif ($answer.result -gt 1) { $out.flagged += @{ index = $out.entries; result = $answer.result } }
              $out.entries += 1
            }
          } finally { [GuardianAmsi]::AmsiCloseSession($script:context, $script:session) }
        }
      } finally { [GuardianAmsi]::AmsiUninitialize($script:context) }
    }
  }
} catch {
  $out.error = $_.Exception.Message
}
[Console]::Out.WriteLine(($out | ConvertTo-Json -Compress -Depth 4))
