import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

/** IPv4/IPv6 address or CIDR (loose: the server validates). */
export const looksLikeIP = (v: string) => /^[\d.]+(\/\d+)?$/.test(v) || v.includes(':')
