"""
============================================================
OTLC GUARDIAN - inbound-check fixtures
// tests . onthelevelconcepts.com
Version: 1.5.0
============================================================

Makes the clean files in this folder that tests/inbound.test.js
judges. Every file here is Guardian-made: written by this script
with ordinary tools, the way a customer's software would write
them. None is a customer's or an employer's file, and none may
ever be added here (the repository is public).

The fixtures built in memory by tests/inbound-fixtures.js are
written byte by byte by Guardian itself. These come from real
writers, so the readers are tested against what real software
produces: object streams in a PDF, a full OOXML workbook, the
header an OpenCASCADE STEP file carries.

    clean.xlsx          openpyxl
    clean.png           Pillow
    clean.jpg           Pillow
    clean.pdf           PyMuPDF, saved with object streams
    clean.dxf           ezdxf (ASCII DXF, AutoCAD 2018 format)
    clean.step          OpenCASCADE (OCP)
    clean.igs           OpenCASCADE (OCP)
    clean-ascii.stl     OpenCASCADE (OCP)
    clean-binary.stl    OpenCASCADE (OCP)

Run:  python tests/fixtures/inbound/make_fixtures.py [name ...]

A file whose writer is not installed in the interpreter is left as
it is and listed as skipped, so the script can be run once with a
Python that has openpyxl, Pillow, PyMuPDF and ezdxf, and once with
one that has OCP. The files are committed; the tests never run this
script. Nothing is fetched and nothing outside this folder is
written.

No fixture may say who made it or where. The writers put the login
name, the machine or a path into a file unless told otherwise (the
IGES author, the last-saved-by field of a DXF, document properties),
so every such field is set to AUTHOR here, and each file is checked
after it is written: the run fails if one holds a word in
PRIVATE_WORDS, the login name or the name of the machine.
tests/inbound.test.js makes the same check on the committed files.

There is no DWG here, on purpose. AutoCAD writes the login name
into every DWG it saves (the "last saved by" drawing property, in
every format back to R14) and gives no way to set it, and a DWG is
checksummed, so the name cannot be taken out afterwards. The tests
judge a DWG built in memory instead, and real drawings go through
the opt-in GUARDIAN_INBOUND_REAL_SAMPLES run.
"""

import getpass
import os
import platform
import re

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
LABEL = "OTLC Guardian test fixture. Made by tests/fixtures/inbound/make_fixtures.py."
AUTHOR = "OTLC Guardian"
# Words no fixture may hold, with the login and host names of this machine.
PRIVATE_WORDS = {"michael", "zion", "zsg", getpass.getuser().lower(), platform.node().lower(),
                 os.environ.get("USERDOMAIN", "").lower()} - {""}


class Skipped(Exception):
    """The writer this fixture needs is not available here."""


def need(module):
    try:
        return __import__(module, fromlist=["_"])
    except ImportError as error:
        raise Skipped(f"{module} is not installed in {sys.executable}") from error


def make_xlsx(path):
    openpyxl = need("openpyxl")
    book = openpyxl.Workbook()
    sheet = book.active
    sheet.title = "Rates"
    sheet.append(["Zone", "Length (in)", "Speed (ft/min)"])
    for row in (("Z1", 30, 180), ("Z2", 30, 180), ("Z3", 36, 200)):
        sheet.append(row)
    sheet["A6"] = LABEL
    book.properties.title = "Guardian fixture"
    book.properties.creator = AUTHOR
    book.properties.lastModifiedBy = AUTHOR
    book.save(path)


def picture():
    image_module = need("PIL.Image")
    draw_module = need("PIL.ImageDraw")
    image = image_module.new("RGB", (160, 90), (244, 244, 240))
    draw = draw_module.Draw(image)
    draw.rectangle((10, 30, 150, 60), outline=(40, 40, 40), width=2)
    for x in range(20, 150, 14):
        draw.ellipse((x, 38, x + 10, 52), outline=(90, 90, 90))
    return image


def make_png(path):
    info = need("PIL.PngImagePlugin").PngInfo()
    info.add_text("Comment", LABEL)
    picture().save(path, "PNG", pnginfo=info)


def make_jpg(path):
    picture().save(path, "JPEG", quality=85, comment=LABEL.encode("ascii"))


def make_pdf(path):
    pymupdf = need("pymupdf")
    doc = pymupdf.open()
    page = doc.new_page(width=612, height=792)
    page.insert_text((72, 96), "Line 3 transfer notes", fontsize=16)
    page.insert_text((72, 126), "Zone lengths and speeds for the merge.", fontsize=11)
    page.insert_text((72, 156), LABEL, fontsize=8)
    doc.set_metadata({"title": "Guardian fixture", "author": AUTHOR, "creator": AUTHOR, "producer": "PyMuPDF"})
    # Object streams and a cross-reference stream: what current PDF writers produce.
    doc.save(path, garbage=3, deflate=True, use_objstms=1)
    doc.close()


def make_dxf(path):
    ezdxf = need("ezdxf")
    doc = ezdxf.new("R2018", setup=True)
    doc.header["$LASTSAVEDBY"] = AUTHOR
    doc.layers.add("CONVEYOR", color=3)
    space = doc.modelspace()
    space.add_lwpolyline([(0, 0), (120, 0), (120, 30), (0, 30)], close=True, dxfattribs={"layer": "CONVEYOR"})
    for x in range(6, 120, 12):
        space.add_circle((x, 15), 1.9, dxfattribs={"layer": "CONVEYOR"})
    space.add_text("ZONE 1", dxfattribs={"height": 2.5}).set_placement((4, 34))
    space.add_text(LABEL, dxfattribs={"height": 1.0}).set_placement((0, -6))
    doc.saveas(path)


def box():
    return need("OCP.BRepPrimAPI").BRepPrimAPI_MakeBox(120.0, 80.0, 40.0).Shape()


def make_step(path):
    control = need("OCP.STEPControl")
    text = need("OCP.TCollection").TCollection_HAsciiString
    writer = control.STEPControl_Writer()
    writer.Transfer(box(), control.STEPControl_StepModelType.STEPControl_AsIs)
    header = need("OCP.APIHeaderSection").APIHeaderSection_MakeHeader(writer.Model())
    header.SetName(text("clean.step"))
    header.SetAuthorValue(1, text(AUTHOR))
    header.SetOrganizationValue(1, text(AUTHOR))
    header.SetAuthorisation(text(""))
    header.SetDescriptionValue(1, text(LABEL))
    if int(writer.Write(str(path))) != 1:
        raise RuntimeError("the STEP writer failed")


def make_iges(path):
    text = need("OCP.TCollection").TCollection_HAsciiString
    writer = need("OCP.IGESControl").IGESControl_Writer("MM", 0)
    writer.AddShape(box())
    writer.ComputeModel()
    # OpenCASCADE writes the login name as the author unless told.
    section = writer.Model().GlobalSection()
    section.SetAuthorName(text(AUTHOR))
    section.SetCompanyName(text(AUTHOR))
    section.SetFileName(text("clean.igs"))
    writer.Model().SetGlobalSection(section)
    if not writer.Write(str(path)):
        raise RuntimeError("the IGES writer failed")


def make_stl(path, ascii_mode):
    shape = box()
    need("OCP.BRepMesh").BRepMesh_IncrementalMesh(shape, 0.5)
    writer = need("OCP.StlAPI").StlAPI_Writer()
    writer.ASCIIMode = ascii_mode
    if not writer.Write(shape, str(path)):
        raise RuntimeError("the STL writer failed")


def private_words(data):
    """The private words in the bytes of a file, read as single bytes and as UTF-16."""
    views = [data.decode("latin-1"), data.decode("utf-16-le", "ignore"), data[1:].decode("utf-16-le", "ignore"),
             data.decode("utf-16-be", "ignore")]
    return sorted({word for word in PRIVATE_WORDS for view in views if re.search(re.escape(word), view, re.IGNORECASE)})


MAKERS = {
    "clean.xlsx": make_xlsx,
    "clean.png": make_png,
    "clean.jpg": make_jpg,
    "clean.pdf": make_pdf,
    "clean.dxf": make_dxf,
    "clean.step": make_step,
    "clean.igs": make_iges,
    "clean-ascii.stl": lambda path: make_stl(path, True),
    "clean-binary.stl": lambda path: make_stl(path, False),
}


def main(names):
    unknown = [name for name in names if name not in MAKERS]
    if unknown:
        print(f"unknown fixture: {', '.join(unknown)}. Known: {', '.join(MAKERS)}")
        return 2
    failed = False
    for name, make in MAKERS.items():
        if names and name not in names:
            continue
        try:
            make(HERE / name)
            found = private_words((HERE / name).read_bytes())
            if found:
                raise RuntimeError(f"the file holds {', '.join(found)}")
            print(f"made     {name} ({(HERE / name).stat().st_size} bytes)")
        except Skipped as why:
            print(f"skipped  {name}: {why}")
        except Exception as error:  # noqa: BLE001 - every writer failure is reported and fails the run
            failed = True
            print(f"FAILED   {name}: {type(error).__name__}: {error}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
