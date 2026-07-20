<!--
Source   : The Lazy Developer (thelazydeveloper.org)
Guide    : https://www.thelazydeveloper.org/form-validation-guide
Index    : https://www.thelazydeveloper.org/resources
Retrieved: 2026-07-20
Stored verbatim. Do not edit the body; re-pull from the source instead.
-->
# Form Validation & Security Guide

A comprehensive template for implementing form validation and security in React and Next.js applications.

## Overview

This guide covers a defence-in-depth approach to form security:

1. **Frontend Validation** - Zod schemas for real-time validation
2. **XSS Sanitization** - Strip malicious content before submission
3. **API Validation** - Server-side re-validation (never trust the client)
4. **CORS Configuration** - Restrict allowed origins

## Dependencies

```bash
npm install zod xss
```

## 1. Frontend Validation (Zod Schemas)

Create `src/lib/validation.ts`:

```typescript
import { z } from 'zod'

// ===========================================
// HELPER: UK Phone Number Validation
// ===========================================
const validateUKPhone = (phone: string): boolean => {
  const digits = phone.replace(/\D/g, '')

  if (digits.startsWith('44')) {
    return digits.length === 12 && (digits.startsWith('447') || digits.startsWith('441') || digits.startsWith('442'))
  } else if (digits.startsWith('0')) {
    return digits.length === 11 && (digits.startsWith('07') || digits.startsWith('01') || digits.startsWith('02') || digits.startsWith('03'))
  } else if (digits.startsWith('7')) {
    return digits.length === 10
  }

  return false
}

// ===========================================
// CONTACT/ENQUIRY FORM SCHEMA
// ===========================================
export const enquiryFormSchema = z.object({
  name: z
    .string()
    .min(2, 'Name must be at least 2 characters')
    .max(100, 'Name must be less than 100 characters')
    .regex(/^[a-zA-Z\s\-'\.]+$/, 'Name can only contain letters, spaces, hyphens, apostrophes and dots'),

  email: z
    .string()
    .email('Please enter a valid email address')
    .max(254, 'Email must be less than 254 characters')
    .toLowerCase(),

  phone: z
    .string()
    .min(10, 'Phone number must be at least 10 digits')
    .max(20, 'Phone number must be less than 20 characters')
    .refine(validateUKPhone, 'Please enter a valid UK phone number (e.g., 07900 123456 or +44 7900 123456)'),

  message: z
    .string()
    .min(10, 'Message must be at least 10 characters')
    .max(2000, 'Message must be less than 2000 characters'),

  agreedToTerms: z
    .boolean()
    .refine(val => val === true, 'You must agree to the terms and privacy policy'),
})

export type EnquiryFormData = z.infer<typeof enquiryFormSchema>

// ===========================================
// NEWSLETTER SCHEMA
// ===========================================
export const newsletterSchema = z.object({
  email: z
    .string()
    .email('Please enter a valid email address')
    .max(254, 'Email must be less than 254 characters')
    .toLowerCase(),
})

export type NewsletterData = z.infer<typeof newsletterSchema>

// ===========================================
// BOOKING/DETAILED FORM SCHEMA
// ===========================================
export const bookingDetailsSchema = z.object({
  parentName: z
    .string()
    .min(2, 'Name must be at least 2 characters')
    .max(100, 'Name must be less than 100 characters')
    .regex(/^[a-zA-Z\s\-'\.]+$/, 'Name can only contain letters, spaces, hyphens, apostrophes and dots'),

  parentEmail: z
    .string()
    .email('Please enter a valid email address')
    .max(254, 'Email must be less than 254 characters')
    .toLowerCase(),

  parentPhone: z
    .string()
    .max(20, 'Phone number must be less than 20 characters')
    .refine(
      (val) => !val || validateUKPhone(val),
      'Please enter a valid UK phone number'
    )
    .optional()
    .or(z.literal('')),

  school: z
    .string()
    .min(2, 'School name must be at least 2 characters')
    .max(200, 'School name must be less than 200 characters'),

  yearGroup: z
    .string()
    .min(1, 'Please select a year group'),

  subjects: z
    .array(z.string())
    .min(1, 'Please select at least one subject'),

  referralSource: z
    .string()
    .min(1, 'Please tell us how you heard about us'),

  comments: z
    .string()
    .max(2000, 'Comments must be less than 2000 characters')
    .optional()
    .or(z.literal('')),
})

export type BookingDetailsData = z.infer<typeof bookingDetailsSchema>

// ===========================================
// HELPER: Get first validation error message
// ===========================================
export const getFirstError = (error: z.ZodError): string => {
  return error.issues[0]?.message || 'Validation failed'
}

// ===========================================
// HELPER: Get all validation errors as object
// ===========================================
export const getFieldErrors = (error: z.ZodError): Record<string, string> => {
  const errors: Record<string, string> = {}
  error.issues.forEach((err: z.ZodIssue) => {
    const path = err.path.join('.')
    if (!errors[path]) {
      errors[path] = err.message
    }
  })
  return errors
}
```

## 2. XSS Sanitization

Create `src/lib/sanitize.ts`:

```typescript
import xss, { IFilterXSSOptions } from 'xss'

const xssOptions: IFilterXSSOptions = {
  whiteList: {},
  stripIgnoreTag: true,
  stripIgnoreTagBody: ['script', 'style'],
}

export const sanitize = (input: string): string => {
  if (!input || typeof input !== 'string') return ''
  return xss(input.trim(), xssOptions)
}

export const sanitizeObject = <T extends Record<string, unknown>>(obj: T): T => {
  const sanitized: Record<string, unknown> = {}

  for (const [key, value] of Object.entries(obj)) {
    if (typeof value === 'string') {
      sanitized[key] = sanitize(value)
    } else if (Array.isArray(value)) {
      sanitized[key] = value.map((item) =>
        typeof item === 'string' ? sanitize(item) : item
      )
    } else if (value !== null && typeof value === 'object') {
      sanitized[key] = sanitizeObject(value as Record<string, unknown>)
    } else {
      sanitized[key] = value
    }
  }

  return sanitized as T
}

export const sanitizeEmail = (email: string): string => {
  if (!email || typeof email !== 'string') return ''
  return email.trim().toLowerCase()
}

export const sanitizePhone = (phone: string): string => {
  if (!phone || typeof phone !== 'string') return ''
  return phone.replace(/[^\d\s\+\-]/g, '').trim()
}
```

## 3. React Form Component Example

```tsx
import { useState } from 'react'
import { enquiryFormSchema, type EnquiryFormData } from '@/lib/validation'
import { sanitize, sanitizeEmail, sanitizePhone } from '@/lib/sanitize'

export function EnquiryForm() {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    phone: '',
    message: '',
    agreedToTerms: false,
  })
  const [errors, setErrors] = useState<Record<string, string>>({})
  const [isSubmitting, setIsSubmitting] = useState(false)

  const validateField = (field: keyof EnquiryFormData, value: unknown) => {
    const fieldSchema = enquiryFormSchema.shape[field]
    const result = fieldSchema.safeParse(value)

    if (!result.success) {
      setErrors(prev => ({
        ...prev,
        [field]: result.error.issues[0]?.message || 'Invalid'
      }))
    } else {
      setErrors(prev => {
        const newErrors = { ...prev }
        delete newErrors[field]
        return newErrors
      })
    }
  }

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    const { name, value, type } = e.target
    const newValue = type === 'checkbox' ? (e.target as HTMLInputElement).checked : value

    setFormData(prev => ({ ...prev, [name]: newValue }))
    validateField(name as keyof EnquiryFormData, newValue)
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsSubmitting(true)

    const result = enquiryFormSchema.safeParse(formData)

    if (!result.success) {
      const fieldErrors: Record<string, string> = {}
      result.error.issues.forEach((err) => {
        const path = err.path.join('.')
        if (!fieldErrors[path]) {
          fieldErrors[path] = err.message
        }
      })
      setErrors(fieldErrors)
      setIsSubmitting(false)
      return
    }

    const sanitizedData = {
      name: sanitize(result.data.name),
      email: sanitizeEmail(result.data.email),
      phone: sanitizePhone(result.data.phone),
      message: sanitize(result.data.message),
      agreedToTerms: result.data.agreedToTerms,
    }

    try {
      const response = await fetch('/api/enquiry', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(sanitizedData),
      })

      if (!response.ok) {
        const data = await response.json()
        if (data.errors) {
          setErrors(data.errors)
        }
        return
      }

      setFormData({ name: '', email: '', phone: '', message: '', agreedToTerms: false })
      setErrors({})
      alert('Form submitted successfully!')
    } catch (error) {
      console.error('Submission error:', error)
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <form onSubmit={handleSubmit}>
      <div>
        <label htmlFor="name">Name</label>
        <input type="text" id="name" name="name" value={formData.name} onChange={handleChange} className={errors.name ? 'border-red-500' : ''} />
        {errors.name && <p className="text-red-500 text-sm">{errors.name}</p>}
      </div>
      <div>
        <label htmlFor="email">Email</label>
        <input type="email" id="email" name="email" value={formData.email} onChange={handleChange} className={errors.email ? 'border-red-500' : ''} />
        {errors.email && <p className="text-red-500 text-sm">{errors.email}</p>}
      </div>
      <div>
        <label htmlFor="phone">Phone</label>
        <input type="tel" id="phone" name="phone" value={formData.phone} onChange={handleChange} className={errors.phone ? 'border-red-500' : ''} />
        {errors.phone && <p className="text-red-500 text-sm">{errors.phone}</p>}
      </div>
      <div>
        <label htmlFor="message">Message</label>
        <textarea id="message" name="message" value={formData.message} onChange={handleChange} className={errors.message ? 'border-red-500' : ''} />
        {errors.message && <p className="text-red-500 text-sm">{errors.message}</p>}
      </div>
      <div>
        <label>
          <input type="checkbox" name="agreedToTerms" checked={formData.agreedToTerms} onChange={handleChange} />
          I agree to the terms and privacy policy
        </label>
        {errors.agreedToTerms && <p className="text-red-500 text-sm">{errors.agreedToTerms}</p>}
      </div>
      <button type="submit" disabled={isSubmitting}>
        {isSubmitting ? 'Submitting...' : 'Submit'}
      </button>
    </form>
  )
}
```

## 4. API Endpoint (Vercel Serverless / Next.js API Route)

### For Vercel Serverless Functions

Create `api/lib/validation.ts` and `api/lib/sanitize.ts` with the same content as the frontend versions.

Create `api/enquiry.ts`:

```typescript
import type { VercelRequest, VercelResponse } from '@vercel/node'
import { enquiryFormSchema, getFieldErrors } from './lib/validation.js'
import { sanitize, sanitizeEmail, sanitizePhone } from './lib/sanitize.js'
import { z } from 'zod'

const ALLOWED_ORIGINS = [
  'https://yourdomain.com',
  'https://www.yourdomain.com',
  'http://localhost:5173',
  'http://localhost:3000',
]

export default async function handler(req: VercelRequest, res: VercelResponse) {
  const origin = req.headers.origin || ''
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin)
  }
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')
  res.setHeader('Access-Control-Allow-Credentials', 'true')

  if (req.method === 'OPTIONS') {
    return res.status(200).end()
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ success: false, error: 'Method not allowed' })
  }

  try {
    const validationResult = enquiryFormSchema.safeParse(req.body)

    if (!validationResult.success) {
      const errors = getFieldErrors(validationResult.error)
      return res.status(400).json({ success: false, error: 'Validation failed', errors })
    }

    const formData = {
      name: sanitize(validationResult.data.name),
      email: sanitizeEmail(validationResult.data.email),
      phone: sanitizePhone(validationResult.data.phone),
      message: sanitize(validationResult.data.message),
    }

    // Process form data (send email, save to CRM, etc.)

    return res.status(200).json({ success: true, message: 'Enquiry submitted successfully' })
  } catch (error) {
    console.error('Enquiry API error:', error)

    if (error instanceof z.ZodError) {
      return res.status(400).json({ success: false, error: 'Validation failed', errors: getFieldErrors(error) })
    }

    return res.status(500).json({ success: false, error: 'Failed to submit enquiry. Please try again.' })
  }
}
```

### For Next.js App Router (API Routes)

Create `app/api/enquiry/route.ts`:

```typescript
import { NextRequest, NextResponse } from 'next/server'
import { enquiryFormSchema, getFieldErrors } from '@/lib/validation'
import { sanitize, sanitizeEmail, sanitizePhone } from '@/lib/sanitize'
import { z } from 'zod'

const ALLOWED_ORIGINS = [
  'https://yourdomain.com',
  'https://www.yourdomain.com',
  'http://localhost:3000',
]

export async function POST(request: NextRequest) {
  const origin = request.headers.get('origin') || ''
  const isAllowedOrigin = ALLOWED_ORIGINS.includes(origin)

  try {
    const body = await request.json()
    const validationResult = enquiryFormSchema.safeParse(body)

    if (!validationResult.success) {
      const errors = getFieldErrors(validationResult.error)
      return NextResponse.json(
        { success: false, error: 'Validation failed', errors },
        { status: 400, headers: isAllowedOrigin ? { 'Access-Control-Allow-Origin': origin } : {} }
      )
    }

    const formData = {
      name: sanitize(validationResult.data.name),
      email: sanitizeEmail(validationResult.data.email),
      phone: sanitizePhone(validationResult.data.phone),
      message: sanitize(validationResult.data.message),
    }

    return NextResponse.json(
      { success: true, message: 'Enquiry submitted successfully' },
      { status: 200, headers: isAllowedOrigin ? { 'Access-Control-Allow-Origin': origin } : {} }
    )
  } catch (error) {
    console.error('Enquiry API error:', error)

    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { success: false, error: 'Validation failed', errors: getFieldErrors(error) },
        { status: 400 }
      )
    }

    return NextResponse.json(
      { success: false, error: 'Failed to submit enquiry. Please try again.' },
      { status: 500 }
    )
  }
}

export async function OPTIONS() {
  return new NextResponse(null, {
    status: 200,
    headers: {
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Allow-Origin': '*',
    },
  })
}
```

## 5. Security Checklist

### Frontend
- [ ] Install zod and xss packages
- [ ] Create validation schemas for all forms
- [ ] Implement real-time field validation on blur/change
- [ ] Sanitize all string inputs before submission
- [ ] Display user-friendly error messages
- [ ] Disable submit button during submission

### API/Backend
- [ ] Re-validate all inputs server-side (never trust client)
- [ ] Sanitize all inputs before processing/storing
- [ ] Configure CORS to whitelist allowed origins only
- [ ] Return structured error responses with field-level errors
- [ ] Log errors for monitoring (but don't expose stack traces)
- [ ] Use HTTPS in production

### Validation Rules Reference

| Field Type | Validation Rules |
|------------|-----------------|
| Name | 2-100 chars, letters/spaces/hyphens/apostrophes only |
| Email | Valid format, max 254 chars, auto-lowercase |
| UK Phone | 07xxx (11 digits), +447xxx (12 digits), or landline formats |
| Message | 10-2000 chars |
| URL | Valid URL format with protocol |
| Dropdown | Must be one of allowed values (use z.enum()) |
| Checkbox | Boolean, refine() for required agreement |
| Array | z.array() with .min(1) for required selections |

## 6. Common Patterns

### Optional Fields with Empty String Fallback
```typescript
comments: z
  .string()
  .max(2000, 'Comments must be less than 2000 characters')
  .optional()
  .or(z.literal('')),
```

### Enum Validation
```typescript
subject: z
  .enum(['maths', 'english', 'science'], {
    message: 'Subject must be maths, english, or science',
  }),
```

### Numeric Validation (Assessment Scores)
```typescript
results: z.object({
  score: z.number().int().min(0).max(100),
  totalQuestions: z.number().int().min(1).max(100),
}),
```

### Conditional Validation
```typescript
phone: z
  .string()
  .max(20)
  .refine(
    (val) => !val || validateUKPhone(val),
    'Please enter a valid UK phone number'
  )
  .optional()
  .or(z.literal('')),
```
