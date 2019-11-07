; /* sp_x86_64_asm
;  *
;  * Copyright (C) 2006-2019 wolfSSL Inc.
;  *
;  * This file is part of wolfSSL.
;  *
;  * wolfSSL is free software; you can redistribute it and/or modify
;  * it under the terms of the GNU General Public License as published by
;  * the Free Software Foundation; either version 2 of the License, or
;  * (at your option) any later version.
;  *
;  * wolfSSL is distributed in the hope that it will be useful,
;  * but WITHOUT ANY WARRANTY; without even the implied warranty of
;  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;  * GNU General Public License for more details.
;  *
;  * You should have received a copy of the GNU General Public License
;  * along with this program; if not, write to the Free Software
;  * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
;  */
DEFINE HAVE_INTEL_AVX2
_text SEGMENT
; /* Multiply a and b into r. (r = a * b)
;  *
;  * r  A single precision integer.
;  * a  A single precision integer.
;  * b  A single precision integer.
;  */
sp_2048_mul_16 PROC
        movq	rcx, rdx
        movq	r9, rcx
        push	r12
        subq	rsp, 128
        ; A[0] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx]
        xorq	r12, r12
        movq	[%rsp], rax
        movq	r11, rdx
        ; A[0] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx]
        xorq	r10, r10
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[1] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+8]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        movq	[%rsp+8], r11
        ; A[0] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx]
        xorq	r11, r11
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[1] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[2] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        movq	[%rsp+16], r12
        ; A[0] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx]
        xorq	r12, r12
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[1] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+8]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[2] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+16]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[3] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+24]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        movq	[%rsp+24], r10
        ; A[0] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx]
        xorq	r10, r10
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[1] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+8]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[2] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+16]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[3] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+24]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[4] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+32]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        movq	[%rsp+32], r11
        ; A[0] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx]
        xorq	r11, r11
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[1] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[2] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[3] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[4] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[5] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        movq	[%rsp+40], r12
        ; A[0] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx]
        xorq	r12, r12
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[1] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+8]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[2] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+16]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[3] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+24]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[4] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+32]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[5] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+40]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[6] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+48]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        movq	[%rsp+48], r10
        ; A[0] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx]
        xorq	r10, r10
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[1] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+8]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[2] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+16]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[3] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+24]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[4] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+32]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[5] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+40]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[6] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+48]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[7] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+56]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        movq	[%rsp+56], r11
        ; A[0] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx]
        xorq	r11, r11
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[1] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[2] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[3] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[4] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[5] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[6] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+48]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[7] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+56]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[8] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+64]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        movq	[%rsp+64], r12
        ; A[0] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx]
        xorq	r12, r12
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[1] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+8]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[2] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+16]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[3] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+24]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[4] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+32]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[5] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+40]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[6] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+48]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[7] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+56]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[8] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+64]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[9] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+72]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        movq	[%rsp+72], r10
        ; A[0] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx]
        xorq	r10, r10
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[1] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+8]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[2] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+16]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[3] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+24]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[4] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+32]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[5] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+40]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[6] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+48]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[7] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+56]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[8] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+64]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[9] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+72]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[10] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+80]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        movq	[%rsp+80], r11
        ; A[0] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx]
        xorq	r11, r11
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[1] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[2] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[3] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[4] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[5] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[6] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+48]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[7] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+56]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[8] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+64]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[9] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+72]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[10] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+80]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[11] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+88]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        movq	[%rsp+88], r12
        ; A[0] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx]
        xorq	r12, r12
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[1] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+8]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[2] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+16]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[3] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+24]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[4] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+32]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[5] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+40]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[6] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+48]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[7] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+56]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[8] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+64]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[9] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+72]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[10] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+80]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[11] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+88]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[12] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+96]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        movq	[%rsp+96], r10
        ; A[0] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx]
        xorq	r10, r10
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[1] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+8]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[2] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+16]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[3] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+24]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[4] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+32]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[5] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+40]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[6] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+48]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[7] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+56]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[8] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+64]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[9] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+72]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[10] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+80]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[11] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+88]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[12] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+96]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[13] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+104]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        movq	[%rsp+104], r11
        ; A[0] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx]
        xorq	r11, r11
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[1] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[2] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[3] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[4] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[5] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[6] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+48]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[7] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+56]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[8] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+64]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[9] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+72]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[10] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+80]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[11] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+88]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[12] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+96]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[13] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+104]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[14] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+112]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        movq	[%rsp+112], r12
        ; A[0] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx]
        xorq	r12, r12
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[1] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+8]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[2] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+16]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[3] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+24]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[4] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+32]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[5] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+40]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[6] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+48]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[7] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+56]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[8] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+64]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[9] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+72]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[10] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+80]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[11] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+88]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[12] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+96]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[13] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+104]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[14] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+112]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[15] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+120]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        movq	[%rsp+120], r10
        ; A[1] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+8]
        xorq	r10, r10
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[2] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+16]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[3] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+24]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[4] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+32]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[5] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+40]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[6] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+48]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[7] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+56]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[8] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+64]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[9] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+72]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[10] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+80]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[11] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+88]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[12] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+96]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[13] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+104]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[14] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+112]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[15] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+120]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        movq	[%r9+128], r11
        ; A[2] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+16]
        xorq	r11, r11
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[3] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[4] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[5] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[6] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+48]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[7] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+56]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[8] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+64]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[9] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+72]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[10] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+80]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[11] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+88]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[12] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+96]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[13] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+104]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[14] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+112]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[15] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+120]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        movq	[%r9+136], r12
        ; A[3] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+24]
        xorq	r12, r12
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[4] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+32]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[5] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+40]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[6] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+48]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[7] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+56]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[8] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+64]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[9] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+72]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[10] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+80]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[11] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+88]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[12] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+96]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[13] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+104]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[14] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+112]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[15] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+120]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        movq	[%r9+144], r10
        ; A[4] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+32]
        xorq	r10, r10
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[5] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+40]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[6] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+48]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[7] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+56]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[8] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+64]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[9] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+72]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[10] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+80]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[11] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+88]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[12] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+96]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[13] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+104]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[14] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+112]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[15] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+120]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        movq	[%r9+152], r11
        ; A[5] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+40]
        xorq	r11, r11
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[6] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+48]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[7] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+56]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[8] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+64]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[9] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+72]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[10] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+80]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[11] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+88]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[12] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+96]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[13] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+104]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[14] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+112]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[15] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+120]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        movq	[%r9+160], r12
        ; A[6] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+48]
        xorq	r12, r12
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[7] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+56]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[8] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+64]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[9] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+72]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[10] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+80]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[11] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+88]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[12] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+96]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[13] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+104]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[14] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+112]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[15] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+120]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        movq	[%r9+168], r10
        ; A[7] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+56]
        xorq	r10, r10
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[8] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+64]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[9] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+72]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[10] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+80]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[11] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+88]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[12] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+96]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[13] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+104]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[14] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+112]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[15] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+120]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        movq	[%r9+176], r11
        ; A[8] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+64]
        xorq	r11, r11
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[9] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+72]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[10] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+80]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[11] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+88]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[12] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+96]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[13] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+104]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[14] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+112]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[15] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+120]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        movq	[%r9+184], r12
        ; A[9] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+72]
        xorq	r12, r12
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[10] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+80]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[11] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+88]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[12] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+96]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[13] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+104]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[14] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+112]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[15] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+120]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        movq	[%r9+192], r10
        ; A[10] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+80]
        xorq	r10, r10
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[11] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+88]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[12] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+96]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[13] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+104]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[14] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+112]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[15] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+120]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        movq	[%r9+200], r11
        ; A[11] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+88]
        xorq	r11, r11
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[12] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+96]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[13] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+104]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[14] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+112]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[15] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+120]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        movq	[%r9+208], r12
        ; A[12] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+96]
        xorq	r12, r12
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[13] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+104]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[14] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+112]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[15] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+120]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        movq	[%r9+216], r10
        ; A[13] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+104]
        xorq	r10, r10
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[14] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+112]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[15] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+120]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        movq	[%r9+224], r11
        ; A[14] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+112]
        xorq	r11, r11
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[15] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+120]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        movq	[%r9+232], r12
        ; A[15] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+120]
        addq	r10, rax
        adcq	r11, rdx
        movq	[%r9+240], r10
        movq	[%r9+248], r11
        movq	rax, [%rsp]
        movq	rdx, [%rsp+8]
        movq	r10, [%rsp+16]
        movq	r11, [%rsp+24]
        movq	[%r9], rax
        movq	[%r9+8], rdx
        movq	[%r9+16], r10
        movq	[%r9+24], r11
        movq	rax, [%rsp+32]
        movq	rdx, [%rsp+40]
        movq	r10, [%rsp+48]
        movq	r11, [%rsp+56]
        movq	[%r9+32], rax
        movq	[%r9+40], rdx
        movq	[%r9+48], r10
        movq	[%r9+56], r11
        movq	rax, [%rsp+64]
        movq	rdx, [%rsp+72]
        movq	r10, [%rsp+80]
        movq	r11, [%rsp+88]
        movq	[%r9+64], rax
        movq	[%r9+72], rdx
        movq	[%r9+80], r10
        movq	[%r9+88], r11
        movq	rax, [%rsp+96]
        movq	rdx, [%rsp+104]
        movq	r10, [%rsp+112]
        movq	r11, [%rsp+120]
        movq	[%r9+96], rax
        movq	[%r9+104], rdx
        movq	[%r9+112], r10
        movq	[%r9+120], r11
        addq	rsp, 128
        pop	r12
        repz retq
sp_2048_mul_16 ENDP
; /* Square a and put result in r. (r = a * a)
;  *
;  * r  A single precision integer.
;  * a  A single precision integer.
;  */
sp_2048_sqr_16 PROC
        movq	rcx, rdx
        movq	r8, rcx
        push	r12
        push	r13
        push	r14
        subq	rsp, 128
        ; A[0] * A[0]
        movq	rax, [%rcx]
        mulq	rax
        xorq	r11, r11
        movq	[%rsp], rax
        movq	r10, rdx
        ; A[0] * A[1]
        movq	rax, [%rcx+8]
        mulq	[%rcx]
        xorq	r9, r9
        addq	r10, rax
        adcq	r11, rdx
        adcq	r9, 0
        addq	r10, rax
        adcq	r11, rdx
        adcq	r9, 0
        movq	[%rsp+8], r10
        ; A[0] * A[2]
        movq	rax, [%rcx+16]
        mulq	[%rcx]
        xorq	r10, r10
        addq	r11, rax
        adcq	r9, rdx
        adcq	r10, 0
        addq	r11, rax
        adcq	r9, rdx
        adcq	r10, 0
        ; A[1] * A[1]
        movq	rax, [%rcx+8]
        mulq	rax
        addq	r11, rax
        adcq	r9, rdx
        adcq	r10, 0
        movq	[%rsp+16], r11
        ; A[0] * A[3]
        movq	rax, [%rcx+24]
        mulq	[%rcx]
        xorq	r11, r11
        addq	r9, rax
        adcq	r10, rdx
        adcq	r11, 0
        addq	r9, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[1] * A[2]
        movq	rax, [%rcx+16]
        mulq	[%rcx+8]
        addq	r9, rax
        adcq	r10, rdx
        adcq	r11, 0
        addq	r9, rax
        adcq	r10, rdx
        adcq	r11, 0
        movq	[%rsp+24], r9
        ; A[0] * A[4]
        movq	rax, [%rcx+32]
        mulq	[%rcx]
        xorq	r9, r9
        addq	r10, rax
        adcq	r11, rdx
        adcq	r9, 0
        addq	r10, rax
        adcq	r11, rdx
        adcq	r9, 0
        ; A[1] * A[3]
        movq	rax, [%rcx+24]
        mulq	[%rcx+8]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r9, 0
        addq	r10, rax
        adcq	r11, rdx
        adcq	r9, 0
        ; A[2] * A[2]
        movq	rax, [%rcx+16]
        mulq	rax
        addq	r10, rax
        adcq	r11, rdx
        adcq	r9, 0
        movq	[%rsp+32], r10
        ; A[0] * A[5]
        movq	rax, [%rcx+40]
        mulq	[%rcx]
        xorq	r10, r10
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[1] * A[4]
        movq	rax, [%rcx+32]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[2] * A[3]
        movq	rax, [%rcx+24]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r11, r12
        adcq	r9, r13
        adcq	r10, r14
        movq	[%rsp+40], r11
        ; A[0] * A[6]
        movq	rax, [%rcx+48]
        mulq	[%rcx]
        xorq	r11, r11
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[1] * A[5]
        movq	rax, [%rcx+40]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[2] * A[4]
        movq	rax, [%rcx+32]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[3] * A[3]
        movq	rax, [%rcx+24]
        mulq	rax
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r9, r12
        adcq	r10, r13
        adcq	r11, r14
        movq	[%rsp+48], r9
        ; A[0] * A[7]
        movq	rax, [%rcx+56]
        mulq	[%rcx]
        xorq	r9, r9
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[1] * A[6]
        movq	rax, [%rcx+48]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[2] * A[5]
        movq	rax, [%rcx+40]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[3] * A[4]
        movq	rax, [%rcx+32]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r10, r12
        adcq	r11, r13
        adcq	r9, r14
        movq	[%rsp+56], r10
        ; A[0] * A[8]
        movq	rax, [%rcx+64]
        mulq	[%rcx]
        xorq	r10, r10
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[1] * A[7]
        movq	rax, [%rcx+56]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[2] * A[6]
        movq	rax, [%rcx+48]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[3] * A[5]
        movq	rax, [%rcx+40]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[4] * A[4]
        movq	rax, [%rcx+32]
        mulq	rax
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r11, r12
        adcq	r9, r13
        adcq	r10, r14
        movq	[%rsp+64], r11
        ; A[0] * A[9]
        movq	rax, [%rcx+72]
        mulq	[%rcx]
        xorq	r11, r11
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[1] * A[8]
        movq	rax, [%rcx+64]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[2] * A[7]
        movq	rax, [%rcx+56]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[3] * A[6]
        movq	rax, [%rcx+48]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[4] * A[5]
        movq	rax, [%rcx+40]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r9, r12
        adcq	r10, r13
        adcq	r11, r14
        movq	[%rsp+72], r9
        ; A[0] * A[10]
        movq	rax, [%rcx+80]
        mulq	[%rcx]
        xorq	r9, r9
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[1] * A[9]
        movq	rax, [%rcx+72]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[2] * A[8]
        movq	rax, [%rcx+64]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[3] * A[7]
        movq	rax, [%rcx+56]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[4] * A[6]
        movq	rax, [%rcx+48]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[5] * A[5]
        movq	rax, [%rcx+40]
        mulq	rax
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r10, r12
        adcq	r11, r13
        adcq	r9, r14
        movq	[%rsp+80], r10
        ; A[0] * A[11]
        movq	rax, [%rcx+88]
        mulq	[%rcx]
        xorq	r10, r10
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[1] * A[10]
        movq	rax, [%rcx+80]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[2] * A[9]
        movq	rax, [%rcx+72]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[3] * A[8]
        movq	rax, [%rcx+64]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[4] * A[7]
        movq	rax, [%rcx+56]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[5] * A[6]
        movq	rax, [%rcx+48]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r11, r12
        adcq	r9, r13
        adcq	r10, r14
        movq	[%rsp+88], r11
        ; A[0] * A[12]
        movq	rax, [%rcx+96]
        mulq	[%rcx]
        xorq	r11, r11
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[1] * A[11]
        movq	rax, [%rcx+88]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[2] * A[10]
        movq	rax, [%rcx+80]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[3] * A[9]
        movq	rax, [%rcx+72]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[4] * A[8]
        movq	rax, [%rcx+64]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[5] * A[7]
        movq	rax, [%rcx+56]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[6] * A[6]
        movq	rax, [%rcx+48]
        mulq	rax
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r9, r12
        adcq	r10, r13
        adcq	r11, r14
        movq	[%rsp+96], r9
        ; A[0] * A[13]
        movq	rax, [%rcx+104]
        mulq	[%rcx]
        xorq	r9, r9
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[1] * A[12]
        movq	rax, [%rcx+96]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[2] * A[11]
        movq	rax, [%rcx+88]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[3] * A[10]
        movq	rax, [%rcx+80]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[4] * A[9]
        movq	rax, [%rcx+72]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[5] * A[8]
        movq	rax, [%rcx+64]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[6] * A[7]
        movq	rax, [%rcx+56]
        mulq	[%rcx+48]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r10, r12
        adcq	r11, r13
        adcq	r9, r14
        movq	[%rsp+104], r10
        ; A[0] * A[14]
        movq	rax, [%rcx+112]
        mulq	[%rcx]
        xorq	r10, r10
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[1] * A[13]
        movq	rax, [%rcx+104]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[2] * A[12]
        movq	rax, [%rcx+96]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[3] * A[11]
        movq	rax, [%rcx+88]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[4] * A[10]
        movq	rax, [%rcx+80]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[5] * A[9]
        movq	rax, [%rcx+72]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[6] * A[8]
        movq	rax, [%rcx+64]
        mulq	[%rcx+48]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[7] * A[7]
        movq	rax, [%rcx+56]
        mulq	rax
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r11, r12
        adcq	r9, r13
        adcq	r10, r14
        movq	[%rsp+112], r11
        ; A[0] * A[15]
        movq	rax, [%rcx+120]
        mulq	[%rcx]
        xorq	r11, r11
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[1] * A[14]
        movq	rax, [%rcx+112]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[2] * A[13]
        movq	rax, [%rcx+104]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[3] * A[12]
        movq	rax, [%rcx+96]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[4] * A[11]
        movq	rax, [%rcx+88]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[5] * A[10]
        movq	rax, [%rcx+80]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[6] * A[9]
        movq	rax, [%rcx+72]
        mulq	[%rcx+48]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[7] * A[8]
        movq	rax, [%rcx+64]
        mulq	[%rcx+56]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r9, r12
        adcq	r10, r13
        adcq	r11, r14
        movq	[%rsp+120], r9
        ; A[1] * A[15]
        movq	rax, [%rcx+120]
        mulq	[%rcx+8]
        xorq	r9, r9
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[2] * A[14]
        movq	rax, [%rcx+112]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[3] * A[13]
        movq	rax, [%rcx+104]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[4] * A[12]
        movq	rax, [%rcx+96]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[5] * A[11]
        movq	rax, [%rcx+88]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[6] * A[10]
        movq	rax, [%rcx+80]
        mulq	[%rcx+48]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[7] * A[9]
        movq	rax, [%rcx+72]
        mulq	[%rcx+56]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[8] * A[8]
        movq	rax, [%rcx+64]
        mulq	rax
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r10, r12
        adcq	r11, r13
        adcq	r9, r14
        movq	[%r8+128], r10
        ; A[2] * A[15]
        movq	rax, [%rcx+120]
        mulq	[%rcx+16]
        xorq	r10, r10
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[3] * A[14]
        movq	rax, [%rcx+112]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[4] * A[13]
        movq	rax, [%rcx+104]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[5] * A[12]
        movq	rax, [%rcx+96]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[6] * A[11]
        movq	rax, [%rcx+88]
        mulq	[%rcx+48]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[7] * A[10]
        movq	rax, [%rcx+80]
        mulq	[%rcx+56]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[8] * A[9]
        movq	rax, [%rcx+72]
        mulq	[%rcx+64]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r11, r12
        adcq	r9, r13
        adcq	r10, r14
        movq	[%r8+136], r11
        ; A[3] * A[15]
        movq	rax, [%rcx+120]
        mulq	[%rcx+24]
        xorq	r11, r11
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[4] * A[14]
        movq	rax, [%rcx+112]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[5] * A[13]
        movq	rax, [%rcx+104]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[6] * A[12]
        movq	rax, [%rcx+96]
        mulq	[%rcx+48]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[7] * A[11]
        movq	rax, [%rcx+88]
        mulq	[%rcx+56]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[8] * A[10]
        movq	rax, [%rcx+80]
        mulq	[%rcx+64]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[9] * A[9]
        movq	rax, [%rcx+72]
        mulq	rax
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r9, r12
        adcq	r10, r13
        adcq	r11, r14
        movq	[%r8+144], r9
        ; A[4] * A[15]
        movq	rax, [%rcx+120]
        mulq	[%rcx+32]
        xorq	r9, r9
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[5] * A[14]
        movq	rax, [%rcx+112]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[6] * A[13]
        movq	rax, [%rcx+104]
        mulq	[%rcx+48]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[7] * A[12]
        movq	rax, [%rcx+96]
        mulq	[%rcx+56]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[8] * A[11]
        movq	rax, [%rcx+88]
        mulq	[%rcx+64]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[9] * A[10]
        movq	rax, [%rcx+80]
        mulq	[%rcx+72]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r10, r12
        adcq	r11, r13
        adcq	r9, r14
        movq	[%r8+152], r10
        ; A[5] * A[15]
        movq	rax, [%rcx+120]
        mulq	[%rcx+40]
        xorq	r10, r10
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[6] * A[14]
        movq	rax, [%rcx+112]
        mulq	[%rcx+48]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[7] * A[13]
        movq	rax, [%rcx+104]
        mulq	[%rcx+56]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[8] * A[12]
        movq	rax, [%rcx+96]
        mulq	[%rcx+64]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[9] * A[11]
        movq	rax, [%rcx+88]
        mulq	[%rcx+72]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[10] * A[10]
        movq	rax, [%rcx+80]
        mulq	rax
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r11, r12
        adcq	r9, r13
        adcq	r10, r14
        movq	[%r8+160], r11
        ; A[6] * A[15]
        movq	rax, [%rcx+120]
        mulq	[%rcx+48]
        xorq	r11, r11
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[7] * A[14]
        movq	rax, [%rcx+112]
        mulq	[%rcx+56]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[8] * A[13]
        movq	rax, [%rcx+104]
        mulq	[%rcx+64]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[9] * A[12]
        movq	rax, [%rcx+96]
        mulq	[%rcx+72]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[10] * A[11]
        movq	rax, [%rcx+88]
        mulq	[%rcx+80]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r9, r12
        adcq	r10, r13
        adcq	r11, r14
        movq	[%r8+168], r9
        ; A[7] * A[15]
        movq	rax, [%rcx+120]
        mulq	[%rcx+56]
        xorq	r9, r9
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[8] * A[14]
        movq	rax, [%rcx+112]
        mulq	[%rcx+64]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[9] * A[13]
        movq	rax, [%rcx+104]
        mulq	[%rcx+72]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[10] * A[12]
        movq	rax, [%rcx+96]
        mulq	[%rcx+80]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[11] * A[11]
        movq	rax, [%rcx+88]
        mulq	rax
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r10, r12
        adcq	r11, r13
        adcq	r9, r14
        movq	[%r8+176], r10
        ; A[8] * A[15]
        movq	rax, [%rcx+120]
        mulq	[%rcx+64]
        xorq	r10, r10
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[9] * A[14]
        movq	rax, [%rcx+112]
        mulq	[%rcx+72]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[10] * A[13]
        movq	rax, [%rcx+104]
        mulq	[%rcx+80]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[11] * A[12]
        movq	rax, [%rcx+96]
        mulq	[%rcx+88]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r11, r12
        adcq	r9, r13
        adcq	r10, r14
        movq	[%r8+184], r11
        ; A[9] * A[15]
        movq	rax, [%rcx+120]
        mulq	[%rcx+72]
        xorq	r11, r11
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[10] * A[14]
        movq	rax, [%rcx+112]
        mulq	[%rcx+80]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[11] * A[13]
        movq	rax, [%rcx+104]
        mulq	[%rcx+88]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[12] * A[12]
        movq	rax, [%rcx+96]
        mulq	rax
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r9, r12
        adcq	r10, r13
        adcq	r11, r14
        movq	[%r8+192], r9
        ; A[10] * A[15]
        movq	rax, [%rcx+120]
        mulq	[%rcx+80]
        xorq	r9, r9
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[11] * A[14]
        movq	rax, [%rcx+112]
        mulq	[%rcx+88]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[12] * A[13]
        movq	rax, [%rcx+104]
        mulq	[%rcx+96]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r10, r12
        adcq	r11, r13
        adcq	r9, r14
        movq	[%r8+200], r10
        ; A[11] * A[15]
        movq	rax, [%rcx+120]
        mulq	[%rcx+88]
        xorq	r10, r10
        addq	r11, rax
        adcq	r9, rdx
        adcq	r10, 0
        addq	r11, rax
        adcq	r9, rdx
        adcq	r10, 0
        ; A[12] * A[14]
        movq	rax, [%rcx+112]
        mulq	[%rcx+96]
        addq	r11, rax
        adcq	r9, rdx
        adcq	r10, 0
        addq	r11, rax
        adcq	r9, rdx
        adcq	r10, 0
        ; A[13] * A[13]
        movq	rax, [%rcx+104]
        mulq	rax
        addq	r11, rax
        adcq	r9, rdx
        adcq	r10, 0
        movq	[%r8+208], r11
        ; A[12] * A[15]
        movq	rax, [%rcx+120]
        mulq	[%rcx+96]
        xorq	r11, r11
        addq	r9, rax
        adcq	r10, rdx
        adcq	r11, 0
        addq	r9, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[13] * A[14]
        movq	rax, [%rcx+112]
        mulq	[%rcx+104]
        addq	r9, rax
        adcq	r10, rdx
        adcq	r11, 0
        addq	r9, rax
        adcq	r10, rdx
        adcq	r11, 0
        movq	[%r8+216], r9
        ; A[13] * A[15]
        movq	rax, [%rcx+120]
        mulq	[%rcx+104]
        xorq	r9, r9
        addq	r10, rax
        adcq	r11, rdx
        adcq	r9, 0
        addq	r10, rax
        adcq	r11, rdx
        adcq	r9, 0
        ; A[14] * A[14]
        movq	rax, [%rcx+112]
        mulq	rax
        addq	r10, rax
        adcq	r11, rdx
        adcq	r9, 0
        movq	[%r8+224], r10
        ; A[14] * A[15]
        movq	rax, [%rcx+120]
        mulq	[%rcx+112]
        xorq	r10, r10
        addq	r11, rax
        adcq	r9, rdx
        adcq	r10, 0
        addq	r11, rax
        adcq	r9, rdx
        adcq	r10, 0
        movq	[%r8+232], r11
        ; A[15] * A[15]
        movq	rax, [%rcx+120]
        mulq	rax
        addq	r9, rax
        adcq	r10, rdx
        movq	[%r8+240], r9
        movq	[%r8+248], r10
        movq	rax, [%rsp]
        movq	rdx, [%rsp+8]
        movq	r12, [%rsp+16]
        movq	r13, [%rsp+24]
        movq	[%r8], rax
        movq	[%r8+8], rdx
        movq	[%r8+16], r12
        movq	[%r8+24], r13
        movq	rax, [%rsp+32]
        movq	rdx, [%rsp+40]
        movq	r12, [%rsp+48]
        movq	r13, [%rsp+56]
        movq	[%r8+32], rax
        movq	[%r8+40], rdx
        movq	[%r8+48], r12
        movq	[%r8+56], r13
        movq	rax, [%rsp+64]
        movq	rdx, [%rsp+72]
        movq	r12, [%rsp+80]
        movq	r13, [%rsp+88]
        movq	[%r8+64], rax
        movq	[%r8+72], rdx
        movq	[%r8+80], r12
        movq	[%r8+88], r13
        movq	rax, [%rsp+96]
        movq	rdx, [%rsp+104]
        movq	r12, [%rsp+112]
        movq	r13, [%rsp+120]
        movq	[%r8+96], rax
        movq	[%r8+104], rdx
        movq	[%r8+112], r12
        movq	[%r8+120], r13
        addq	rsp, 128
        pop	r14
        pop	r13
        pop	r12
        repz retq
sp_2048_sqr_16 ENDP
IFDEF HAVE_INTEL_AVX2
; /* Multiply a and b into r. (r = a * b)
;  *
;  * r   Result of multiplication.
;  * a   First number to multiply.
;  * b   Second number to multiply.
;  */
sp_2048_mul_avx2_16 PROC
        movq	rbp, r8
        movq	rax, rdx
        push	rbp
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        subq	rsp, 128
        movq	rdi, 0
        movq	rdx, [%rax]
        ; A[0] * B[0]
        mulx	r11, r10, [%rbp]
        ; A[0] * B[1]
        mulx	r12, r8, [%rbp+8]
        movq	[%rsp], r10
        adcxq	r11, r8
        ; A[0] * B[2]
        mulx	r13, r8, [%rbp+16]
        movq	[%rsp+8], r11
        adcxq	r12, r8
        ; A[0] * B[3]
        mulx	r14, r8, [%rbp+24]
        movq	[%rsp+16], r12
        adcxq	r13, r8
        movq	[%rsp+24], r13
        ; A[0] * B[4]
        mulx	r10, r8, [%rbp+32]
        adcxq	r14, r8
        ; A[0] * B[5]
        mulx	r11, r8, [%rbp+40]
        movq	[%rsp+32], r14
        adcxq	r10, r8
        ; A[0] * B[6]
        mulx	r12, r8, [%rbp+48]
        movq	[%rsp+40], r10
        adcxq	r11, r8
        ; A[0] * B[7]
        mulx	r13, r8, [%rbp+56]
        movq	[%rsp+48], r11
        adcxq	r12, r8
        movq	[%rsp+56], r12
        ; A[0] * B[8]
        mulx	r14, r8, [%rbp+64]
        adcxq	r13, r8
        ; A[0] * B[9]
        mulx	r10, r8, [%rbp+72]
        movq	[%rsp+64], r13
        adcxq	r14, r8
        ; A[0] * B[10]
        mulx	r11, r8, [%rbp+80]
        movq	[%rsp+72], r14
        adcxq	r10, r8
        ; A[0] * B[11]
        mulx	r12, r8, [%rbp+88]
        movq	[%rsp+80], r10
        adcxq	r11, r8
        movq	[%rsp+88], r11
        ; A[0] * B[12]
        mulx	r13, r8, [%rbp+96]
        adcxq	r12, r8
        ; A[0] * B[13]
        mulx	r14, r8, [%rbp+104]
        movq	[%rsp+96], r12
        adcxq	r13, r8
        ; A[0] * B[14]
        mulx	r10, r8, [%rbp+112]
        movq	[%rsp+104], r13
        adcxq	r14, r8
        ; A[0] * B[15]
        mulx	r11, r8, [%rbp+120]
        movq	rsi, r14
        adcxq	r10, r8
        adcxq	r11, rdi
        movq	r15, rdi
        adcxq	r15, rdi
        movq	rbx, r10
        movq	[%rcx+128], r11
        movq	rdx, [%rax+8]
        movq	r11, [%rsp+8]
        movq	r12, [%rsp+16]
        movq	r13, [%rsp+24]
        movq	r14, [%rsp+32]
        movq	r10, [%rsp+40]
        ; A[1] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[1] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	[%rsp+8], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[1] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	[%rsp+16], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[1] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	[%rsp+24], r13
        adcxq	r14, r8
        adoxq	r10, r9
        movq	[%rsp+32], r14
        movq	r11, [%rsp+48]
        movq	r12, [%rsp+56]
        movq	r13, [%rsp+64]
        movq	r14, [%rsp+72]
        ; A[1] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[1] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	[%rsp+40], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[1] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	[%rsp+48], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[1] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	[%rsp+56], r12
        adcxq	r13, r8
        adoxq	r14, r9
        movq	[%rsp+64], r13
        movq	r10, [%rsp+80]
        movq	r11, [%rsp+88]
        movq	r12, [%rsp+96]
        movq	r13, [%rsp+104]
        ; A[1] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[1] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	[%rsp+72], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[1] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	[%rsp+80], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[1] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	[%rsp+88], r11
        adcxq	r12, r8
        adoxq	r13, r9
        movq	[%rsp+96], r12
        movq	r14, rsi
        movq	r10, rbx
        movq	r11, [%rcx+128]
        ; A[1] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[1] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	[%rsp+104], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[1] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	rsi, r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[1] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	rbx, r10
        movq	r12, rdi
        adcxq	r11, r8
        adoxq	r12, r9
        adcxq	r12, r15
        movq	r15, rdi
        adoxq	r15, rdi
        adcxq	r15, rdi
        movq	[%rcx+128], r11
        movq	[%rcx+136], r12
        movq	rdx, [%rax+16]
        movq	r12, [%rsp+16]
        movq	r13, [%rsp+24]
        movq	r14, [%rsp+32]
        movq	r10, [%rsp+40]
        movq	r11, [%rsp+48]
        ; A[2] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[2] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	[%rsp+16], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[2] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	[%rsp+24], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[2] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	[%rsp+32], r14
        adcxq	r10, r8
        adoxq	r11, r9
        movq	[%rsp+40], r10
        movq	r12, [%rsp+56]
        movq	r13, [%rsp+64]
        movq	r14, [%rsp+72]
        movq	r10, [%rsp+80]
        ; A[2] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[2] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	[%rsp+48], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[2] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	[%rsp+56], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[2] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	[%rsp+64], r13
        adcxq	r14, r8
        adoxq	r10, r9
        movq	[%rsp+72], r14
        movq	r11, [%rsp+88]
        movq	r12, [%rsp+96]
        movq	r13, [%rsp+104]
        movq	r14, rsi
        ; A[2] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[2] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	[%rsp+80], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[2] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	[%rsp+88], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[2] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	[%rsp+96], r12
        adcxq	r13, r8
        adoxq	r14, r9
        movq	[%rsp+104], r13
        movq	r10, rbx
        movq	r11, [%rcx+128]
        movq	r12, [%rcx+136]
        ; A[2] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[2] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	rsi, r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[2] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	rbx, r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[2] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	[%rcx+128], r11
        movq	r13, rdi
        adcxq	r12, r8
        adoxq	r13, r9
        adcxq	r13, r15
        movq	r15, rdi
        adoxq	r15, rdi
        adcxq	r15, rdi
        movq	[%rcx+136], r12
        movq	[%rcx+144], r13
        movq	rdx, [%rax+24]
        movq	r13, [%rsp+24]
        movq	r14, [%rsp+32]
        movq	r10, [%rsp+40]
        movq	r11, [%rsp+48]
        movq	r12, [%rsp+56]
        ; A[3] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[3] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	[%rsp+24], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[3] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	[%rsp+32], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[3] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	[%rsp+40], r10
        adcxq	r11, r8
        adoxq	r12, r9
        movq	[%rsp+48], r11
        movq	r13, [%rsp+64]
        movq	r14, [%rsp+72]
        movq	r10, [%rsp+80]
        movq	r11, [%rsp+88]
        ; A[3] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[3] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	[%rsp+56], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[3] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	[%rsp+64], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[3] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	[%rsp+72], r14
        adcxq	r10, r8
        adoxq	r11, r9
        movq	[%rsp+80], r10
        movq	r12, [%rsp+96]
        movq	r13, [%rsp+104]
        movq	r14, rsi
        movq	r10, rbx
        ; A[3] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[3] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	[%rsp+88], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[3] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	[%rsp+96], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[3] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	[%rsp+104], r13
        adcxq	r14, r8
        adoxq	r10, r9
        movq	rsi, r14
        movq	r11, [%rcx+128]
        movq	r12, [%rcx+136]
        movq	r13, [%rcx+144]
        ; A[3] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[3] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	rbx, r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[3] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	[%rcx+128], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[3] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	[%rcx+136], r12
        movq	r14, rdi
        adcxq	r13, r8
        adoxq	r14, r9
        adcxq	r14, r15
        movq	r15, rdi
        adoxq	r15, rdi
        adcxq	r15, rdi
        movq	[%rcx+144], r13
        movq	[%rcx+152], r14
        movq	rdx, [%rax+32]
        movq	r14, [%rsp+32]
        movq	r10, [%rsp+40]
        movq	r11, [%rsp+48]
        movq	r12, [%rsp+56]
        movq	r13, [%rsp+64]
        ; A[4] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[4] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	[%rsp+32], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[4] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	[%rsp+40], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[4] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	[%rsp+48], r11
        adcxq	r12, r8
        adoxq	r13, r9
        movq	[%rsp+56], r12
        movq	r14, [%rsp+72]
        movq	r10, [%rsp+80]
        movq	r11, [%rsp+88]
        movq	r12, [%rsp+96]
        ; A[4] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[4] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	[%rsp+64], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[4] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	[%rsp+72], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[4] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	[%rsp+80], r10
        adcxq	r11, r8
        adoxq	r12, r9
        movq	[%rsp+88], r11
        movq	r13, [%rsp+104]
        movq	r14, rsi
        movq	r10, rbx
        movq	r11, [%rcx+128]
        ; A[4] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[4] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	[%rsp+96], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[4] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	[%rsp+104], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[4] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	rsi, r14
        adcxq	r10, r8
        adoxq	r11, r9
        movq	rbx, r10
        movq	r12, [%rcx+136]
        movq	r13, [%rcx+144]
        movq	r14, [%rcx+152]
        ; A[4] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[4] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	[%rcx+128], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[4] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	[%rcx+136], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[4] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	[%rcx+144], r13
        movq	r10, rdi
        adcxq	r14, r8
        adoxq	r10, r9
        adcxq	r10, r15
        movq	r15, rdi
        adoxq	r15, rdi
        adcxq	r15, rdi
        movq	[%rcx+152], r14
        movq	[%rcx+160], r10
        movq	rdx, [%rax+40]
        movq	r10, [%rsp+40]
        movq	r11, [%rsp+48]
        movq	r12, [%rsp+56]
        movq	r13, [%rsp+64]
        movq	r14, [%rsp+72]
        ; A[5] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[5] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	[%rsp+40], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[5] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	[%rsp+48], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[5] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	[%rsp+56], r12
        adcxq	r13, r8
        adoxq	r14, r9
        movq	[%rsp+64], r13
        movq	r10, [%rsp+80]
        movq	r11, [%rsp+88]
        movq	r12, [%rsp+96]
        movq	r13, [%rsp+104]
        ; A[5] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[5] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	[%rsp+72], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[5] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	[%rsp+80], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[5] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	[%rsp+88], r11
        adcxq	r12, r8
        adoxq	r13, r9
        movq	[%rsp+96], r12
        movq	r14, rsi
        movq	r10, rbx
        movq	r11, [%rcx+128]
        movq	r12, [%rcx+136]
        ; A[5] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[5] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	[%rsp+104], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[5] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	rsi, r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[5] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	rbx, r10
        adcxq	r11, r8
        adoxq	r12, r9
        movq	[%rcx+128], r11
        movq	r13, [%rcx+144]
        movq	r14, [%rcx+152]
        movq	r10, [%rcx+160]
        ; A[5] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[5] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	[%rcx+136], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[5] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	[%rcx+144], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[5] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	[%rcx+152], r14
        movq	r11, rdi
        adcxq	r10, r8
        adoxq	r11, r9
        adcxq	r11, r15
        movq	r15, rdi
        adoxq	r15, rdi
        adcxq	r15, rdi
        movq	[%rcx+160], r10
        movq	[%rcx+168], r11
        movq	rdx, [%rax+48]
        movq	r11, [%rsp+48]
        movq	r12, [%rsp+56]
        movq	r13, [%rsp+64]
        movq	r14, [%rsp+72]
        movq	r10, [%rsp+80]
        ; A[6] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[6] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	[%rsp+48], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[6] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	[%rsp+56], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[6] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	[%rsp+64], r13
        adcxq	r14, r8
        adoxq	r10, r9
        movq	[%rsp+72], r14
        movq	r11, [%rsp+88]
        movq	r12, [%rsp+96]
        movq	r13, [%rsp+104]
        movq	r14, rsi
        ; A[6] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[6] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	[%rsp+80], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[6] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	[%rsp+88], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[6] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	[%rsp+96], r12
        adcxq	r13, r8
        adoxq	r14, r9
        movq	[%rsp+104], r13
        movq	r10, rbx
        movq	r11, [%rcx+128]
        movq	r12, [%rcx+136]
        movq	r13, [%rcx+144]
        ; A[6] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[6] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	rsi, r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[6] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	rbx, r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[6] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	[%rcx+128], r11
        adcxq	r12, r8
        adoxq	r13, r9
        movq	[%rcx+136], r12
        movq	r14, [%rcx+152]
        movq	r10, [%rcx+160]
        movq	r11, [%rcx+168]
        ; A[6] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[6] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	[%rcx+144], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[6] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	[%rcx+152], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[6] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	[%rcx+160], r10
        movq	r12, rdi
        adcxq	r11, r8
        adoxq	r12, r9
        adcxq	r12, r15
        movq	r15, rdi
        adoxq	r15, rdi
        adcxq	r15, rdi
        movq	[%rcx+168], r11
        movq	[%rcx+176], r12
        movq	rdx, [%rax+56]
        movq	r12, [%rsp+56]
        movq	r13, [%rsp+64]
        movq	r14, [%rsp+72]
        movq	r10, [%rsp+80]
        movq	r11, [%rsp+88]
        ; A[7] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[7] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	[%rsp+56], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[7] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	[%rsp+64], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[7] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	[%rsp+72], r14
        adcxq	r10, r8
        adoxq	r11, r9
        movq	[%rsp+80], r10
        movq	r12, [%rsp+96]
        movq	r13, [%rsp+104]
        movq	r14, rsi
        movq	r10, rbx
        ; A[7] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[7] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	[%rsp+88], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[7] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	[%rsp+96], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[7] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	[%rsp+104], r13
        adcxq	r14, r8
        adoxq	r10, r9
        movq	rsi, r14
        movq	r11, [%rcx+128]
        movq	r12, [%rcx+136]
        movq	r13, [%rcx+144]
        movq	r14, [%rcx+152]
        ; A[7] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[7] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	rbx, r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[7] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	[%rcx+128], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[7] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	[%rcx+136], r12
        adcxq	r13, r8
        adoxq	r14, r9
        movq	[%rcx+144], r13
        movq	r10, [%rcx+160]
        movq	r11, [%rcx+168]
        movq	r12, [%rcx+176]
        ; A[7] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[7] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	[%rcx+152], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[7] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	[%rcx+160], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[7] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	[%rcx+168], r11
        movq	r13, rdi
        adcxq	r12, r8
        adoxq	r13, r9
        adcxq	r13, r15
        movq	r15, rdi
        adoxq	r15, rdi
        adcxq	r15, rdi
        movq	[%rcx+176], r12
        movq	[%rcx+184], r13
        movq	rdx, [%rax+64]
        movq	r13, [%rsp+64]
        movq	r14, [%rsp+72]
        movq	r10, [%rsp+80]
        movq	r11, [%rsp+88]
        movq	r12, [%rsp+96]
        ; A[8] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[8] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	[%rsp+64], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[8] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	[%rsp+72], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[8] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	[%rsp+80], r10
        adcxq	r11, r8
        adoxq	r12, r9
        movq	[%rsp+88], r11
        movq	r13, [%rsp+104]
        movq	r14, rsi
        movq	r10, rbx
        movq	r11, [%rcx+128]
        ; A[8] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[8] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	[%rsp+96], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[8] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	[%rsp+104], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[8] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	rsi, r14
        adcxq	r10, r8
        adoxq	r11, r9
        movq	rbx, r10
        movq	r12, [%rcx+136]
        movq	r13, [%rcx+144]
        movq	r14, [%rcx+152]
        movq	r10, [%rcx+160]
        ; A[8] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[8] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	[%rcx+128], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[8] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	[%rcx+136], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[8] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	[%rcx+144], r13
        adcxq	r14, r8
        adoxq	r10, r9
        movq	[%rcx+152], r14
        movq	r11, [%rcx+168]
        movq	r12, [%rcx+176]
        movq	r13, [%rcx+184]
        ; A[8] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[8] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	[%rcx+160], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[8] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	[%rcx+168], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[8] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	[%rcx+176], r12
        movq	r14, rdi
        adcxq	r13, r8
        adoxq	r14, r9
        adcxq	r14, r15
        movq	r15, rdi
        adoxq	r15, rdi
        adcxq	r15, rdi
        movq	[%rcx+184], r13
        movq	[%rcx+192], r14
        movq	rdx, [%rax+72]
        movq	r14, [%rsp+72]
        movq	r10, [%rsp+80]
        movq	r11, [%rsp+88]
        movq	r12, [%rsp+96]
        movq	r13, [%rsp+104]
        ; A[9] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[9] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	[%rsp+72], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[9] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	[%rsp+80], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[9] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	[%rsp+88], r11
        adcxq	r12, r8
        adoxq	r13, r9
        movq	[%rsp+96], r12
        movq	r14, rsi
        movq	r10, rbx
        movq	r11, [%rcx+128]
        movq	r12, [%rcx+136]
        ; A[9] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[9] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	[%rsp+104], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[9] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	rsi, r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[9] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	rbx, r10
        adcxq	r11, r8
        adoxq	r12, r9
        movq	[%rcx+128], r11
        movq	r13, [%rcx+144]
        movq	r14, [%rcx+152]
        movq	r10, [%rcx+160]
        movq	r11, [%rcx+168]
        ; A[9] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[9] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	[%rcx+136], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[9] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	[%rcx+144], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[9] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	[%rcx+152], r14
        adcxq	r10, r8
        adoxq	r11, r9
        movq	[%rcx+160], r10
        movq	r12, [%rcx+176]
        movq	r13, [%rcx+184]
        movq	r14, [%rcx+192]
        ; A[9] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[9] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	[%rcx+168], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[9] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	[%rcx+176], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[9] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	[%rcx+184], r13
        movq	r10, rdi
        adcxq	r14, r8
        adoxq	r10, r9
        adcxq	r10, r15
        movq	r15, rdi
        adoxq	r15, rdi
        adcxq	r15, rdi
        movq	[%rcx+192], r14
        movq	[%rcx+200], r10
        movq	rdx, [%rax+80]
        movq	r10, [%rsp+80]
        movq	r11, [%rsp+88]
        movq	r12, [%rsp+96]
        movq	r13, [%rsp+104]
        movq	r14, rsi
        ; A[10] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[10] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	[%rsp+80], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[10] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	[%rsp+88], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[10] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	[%rsp+96], r12
        adcxq	r13, r8
        adoxq	r14, r9
        movq	[%rsp+104], r13
        movq	r10, rbx
        movq	r11, [%rcx+128]
        movq	r12, [%rcx+136]
        movq	r13, [%rcx+144]
        ; A[10] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[10] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	rsi, r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[10] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	rbx, r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[10] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	[%rcx+128], r11
        adcxq	r12, r8
        adoxq	r13, r9
        movq	[%rcx+136], r12
        movq	r14, [%rcx+152]
        movq	r10, [%rcx+160]
        movq	r11, [%rcx+168]
        movq	r12, [%rcx+176]
        ; A[10] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[10] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	[%rcx+144], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[10] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	[%rcx+152], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[10] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	[%rcx+160], r10
        adcxq	r11, r8
        adoxq	r12, r9
        movq	[%rcx+168], r11
        movq	r13, [%rcx+184]
        movq	r14, [%rcx+192]
        movq	r10, [%rcx+200]
        ; A[10] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[10] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	[%rcx+176], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[10] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	[%rcx+184], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[10] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	[%rcx+192], r14
        movq	r11, rdi
        adcxq	r10, r8
        adoxq	r11, r9
        adcxq	r11, r15
        movq	r15, rdi
        adoxq	r15, rdi
        adcxq	r15, rdi
        movq	[%rcx+200], r10
        movq	[%rcx+208], r11
        movq	rdx, [%rax+88]
        movq	r11, [%rsp+88]
        movq	r12, [%rsp+96]
        movq	r13, [%rsp+104]
        movq	r14, rsi
        movq	r10, rbx
        ; A[11] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[11] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	[%rsp+88], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[11] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	[%rsp+96], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[11] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	[%rsp+104], r13
        adcxq	r14, r8
        adoxq	r10, r9
        movq	rsi, r14
        movq	r11, [%rcx+128]
        movq	r12, [%rcx+136]
        movq	r13, [%rcx+144]
        movq	r14, [%rcx+152]
        ; A[11] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[11] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	rbx, r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[11] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	[%rcx+128], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[11] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	[%rcx+136], r12
        adcxq	r13, r8
        adoxq	r14, r9
        movq	[%rcx+144], r13
        movq	r10, [%rcx+160]
        movq	r11, [%rcx+168]
        movq	r12, [%rcx+176]
        movq	r13, [%rcx+184]
        ; A[11] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[11] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	[%rcx+152], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[11] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	[%rcx+160], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[11] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	[%rcx+168], r11
        adcxq	r12, r8
        adoxq	r13, r9
        movq	[%rcx+176], r12
        movq	r14, [%rcx+192]
        movq	r10, [%rcx+200]
        movq	r11, [%rcx+208]
        ; A[11] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[11] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	[%rcx+184], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[11] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	[%rcx+192], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[11] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	[%rcx+200], r10
        movq	r12, rdi
        adcxq	r11, r8
        adoxq	r12, r9
        adcxq	r12, r15
        movq	r15, rdi
        adoxq	r15, rdi
        adcxq	r15, rdi
        movq	[%rcx+208], r11
        movq	[%rcx+216], r12
        movq	rdx, [%rax+96]
        movq	r12, [%rsp+96]
        movq	r13, [%rsp+104]
        movq	r14, rsi
        movq	r10, rbx
        movq	r11, [%rcx+128]
        ; A[12] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[12] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	[%rsp+96], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[12] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	[%rsp+104], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[12] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	rsi, r14
        adcxq	r10, r8
        adoxq	r11, r9
        movq	rbx, r10
        movq	r12, [%rcx+136]
        movq	r13, [%rcx+144]
        movq	r14, [%rcx+152]
        movq	r10, [%rcx+160]
        ; A[12] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[12] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	[%rcx+128], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[12] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	[%rcx+136], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[12] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	[%rcx+144], r13
        adcxq	r14, r8
        adoxq	r10, r9
        movq	[%rcx+152], r14
        movq	r11, [%rcx+168]
        movq	r12, [%rcx+176]
        movq	r13, [%rcx+184]
        movq	r14, [%rcx+192]
        ; A[12] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[12] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	[%rcx+160], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[12] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	[%rcx+168], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[12] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	[%rcx+176], r12
        adcxq	r13, r8
        adoxq	r14, r9
        movq	[%rcx+184], r13
        movq	r10, [%rcx+200]
        movq	r11, [%rcx+208]
        movq	r12, [%rcx+216]
        ; A[12] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[12] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	[%rcx+192], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[12] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	[%rcx+200], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[12] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	[%rcx+208], r11
        movq	r13, rdi
        adcxq	r12, r8
        adoxq	r13, r9
        adcxq	r13, r15
        movq	r15, rdi
        adoxq	r15, rdi
        adcxq	r15, rdi
        movq	[%rcx+216], r12
        movq	[%rcx+224], r13
        movq	rdx, [%rax+104]
        movq	r13, [%rsp+104]
        movq	r14, rsi
        movq	r10, rbx
        movq	r11, [%rcx+128]
        movq	r12, [%rcx+136]
        ; A[13] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[13] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	[%rsp+104], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[13] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	rsi, r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[13] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	rbx, r10
        adcxq	r11, r8
        adoxq	r12, r9
        movq	[%rcx+128], r11
        movq	r13, [%rcx+144]
        movq	r14, [%rcx+152]
        movq	r10, [%rcx+160]
        movq	r11, [%rcx+168]
        ; A[13] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[13] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	[%rcx+136], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[13] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	[%rcx+144], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[13] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	[%rcx+152], r14
        adcxq	r10, r8
        adoxq	r11, r9
        movq	[%rcx+160], r10
        movq	r12, [%rcx+176]
        movq	r13, [%rcx+184]
        movq	r14, [%rcx+192]
        movq	r10, [%rcx+200]
        ; A[13] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[13] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	[%rcx+168], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[13] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	[%rcx+176], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[13] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	[%rcx+184], r13
        adcxq	r14, r8
        adoxq	r10, r9
        movq	[%rcx+192], r14
        movq	r11, [%rcx+208]
        movq	r12, [%rcx+216]
        movq	r13, [%rcx+224]
        ; A[13] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[13] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	[%rcx+200], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[13] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	[%rcx+208], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[13] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	[%rcx+216], r12
        movq	r14, rdi
        adcxq	r13, r8
        adoxq	r14, r9
        adcxq	r14, r15
        movq	r15, rdi
        adoxq	r15, rdi
        adcxq	r15, rdi
        movq	[%rcx+224], r13
        movq	[%rcx+232], r14
        movq	rdx, [%rax+112]
        movq	r14, rsi
        movq	r10, rbx
        movq	r11, [%rcx+128]
        movq	r12, [%rcx+136]
        movq	r13, [%rcx+144]
        ; A[14] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[14] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	rsi, r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[14] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	rbx, r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[14] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	[%rcx+128], r11
        adcxq	r12, r8
        adoxq	r13, r9
        movq	[%rcx+136], r12
        movq	r14, [%rcx+152]
        movq	r10, [%rcx+160]
        movq	r11, [%rcx+168]
        movq	r12, [%rcx+176]
        ; A[14] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[14] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	[%rcx+144], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[14] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	[%rcx+152], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[14] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	[%rcx+160], r10
        adcxq	r11, r8
        adoxq	r12, r9
        movq	[%rcx+168], r11
        movq	r13, [%rcx+184]
        movq	r14, [%rcx+192]
        movq	r10, [%rcx+200]
        movq	r11, [%rcx+208]
        ; A[14] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[14] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	[%rcx+176], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[14] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	[%rcx+184], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[14] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	[%rcx+192], r14
        adcxq	r10, r8
        adoxq	r11, r9
        movq	[%rcx+200], r10
        movq	r12, [%rcx+216]
        movq	r13, [%rcx+224]
        movq	r14, [%rcx+232]
        ; A[14] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[14] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	[%rcx+208], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[14] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	[%rcx+216], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[14] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	[%rcx+224], r13
        movq	r10, rdi
        adcxq	r14, r8
        adoxq	r10, r9
        adcxq	r10, r15
        movq	r15, rdi
        adoxq	r15, rdi
        adcxq	r15, rdi
        movq	[%rcx+232], r14
        movq	[%rcx+240], r10
        movq	rdx, [%rax+120]
        movq	r10, rbx
        movq	r11, [%rcx+128]
        movq	r12, [%rcx+136]
        movq	r13, [%rcx+144]
        movq	r14, [%rcx+152]
        ; A[15] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[15] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	rbx, r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[15] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	[%rcx+128], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[15] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	[%rcx+136], r12
        adcxq	r13, r8
        adoxq	r14, r9
        movq	[%rcx+144], r13
        movq	r10, [%rcx+160]
        movq	r11, [%rcx+168]
        movq	r12, [%rcx+176]
        movq	r13, [%rcx+184]
        ; A[15] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[15] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	[%rcx+152], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[15] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	[%rcx+160], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[15] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	[%rcx+168], r11
        adcxq	r12, r8
        adoxq	r13, r9
        movq	[%rcx+176], r12
        movq	r14, [%rcx+192]
        movq	r10, [%rcx+200]
        movq	r11, [%rcx+208]
        movq	r12, [%rcx+216]
        ; A[15] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[15] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	[%rcx+184], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[15] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	[%rcx+192], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[15] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	[%rcx+200], r10
        adcxq	r11, r8
        adoxq	r12, r9
        movq	[%rcx+208], r11
        movq	r13, [%rcx+224]
        movq	r14, [%rcx+232]
        movq	r10, [%rcx+240]
        ; A[15] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[15] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	[%rcx+216], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[15] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	[%rcx+224], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[15] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	[%rcx+232], r14
        movq	r11, rdi
        adcxq	r10, r8
        adoxq	r11, r9
        adcxq	r11, r15
        movq	[%rcx+240], r10
        movq	[%rcx+248], r11
        movq	r10, [%rsp]
        movq	r11, [%rsp+8]
        movq	r12, [%rsp+16]
        movq	r13, [%rsp+24]
        movq	[%rcx], r10
        movq	[%rcx+8], r11
        movq	[%rcx+16], r12
        movq	[%rcx+24], r13
        movq	r10, [%rsp+32]
        movq	r11, [%rsp+40]
        movq	r12, [%rsp+48]
        movq	r13, [%rsp+56]
        movq	[%rcx+32], r10
        movq	[%rcx+40], r11
        movq	[%rcx+48], r12
        movq	[%rcx+56], r13
        movq	r10, [%rsp+64]
        movq	r11, [%rsp+72]
        movq	r12, [%rsp+80]
        movq	r13, [%rsp+88]
        movq	[%rcx+64], r10
        movq	[%rcx+72], r11
        movq	[%rcx+80], r12
        movq	[%rcx+88], r13
        movq	r10, [%rsp+96]
        movq	r11, [%rsp+104]
        movq	r12, rsi
        movq	r13, rbx
        movq	[%rcx+96], r10
        movq	[%rcx+104], r11
        movq	[%rcx+112], r12
        movq	[%rcx+120], r13
        addq	rsp, 128
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rbp
        repz retq
sp_2048_mul_avx2_16 ENDP
ENDIF
IFDEF HAVE_INTEL_AVX2
; /* Square a and put result in r. (r = a * a)
;  *
;  * r  A single precision integer.
;  * a  A single precision integer.
;  */
sp_2048_sqr_avx2_16 PROC
        movq	r8, rdx
        movq	r9, rcx
        push	rbp
        push	r12
        push	r13
        push	r14
        push	r15
        subq	rsp, 128
        cmpq	r8, r9
        movq	rbp, rsp
        cmovne	rbp, r9
        xorq	r14, r14
        ; Diagonal 1
        xorq	r10, r10
        xorq	r11, r11
        xorq	r12, r12
        xorq	r13, r13
        ; A[1] x A[0]
        movq	rdx, [%r8]
        mulxq	r11, r10, [%r8+8]
        ; A[2] x A[0]
        mulxq	rcx, rax, [%r8+16]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[3] x A[0]
        mulxq	rcx, rax, [%r8+24]
        adcxq	r12, rax
        adoxq	r13, rcx
        movq	[%rbp+8], r10
        movq	[%rbp+16], r11
        movq	[%rbp+24], r12
        movq	r10, r14
        movq	r11, r14
        movq	r12, r14
        ; A[4] x A[0]
        mulxq	rcx, rax, [%r8+32]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[5] x A[0]
        mulxq	rcx, rax, [%r8+40]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[6] x A[0]
        mulxq	rcx, rax, [%r8+48]
        adcxq	r11, rax
        adoxq	r12, rcx
        movq	[%rbp+32], r13
        movq	[%rbp+40], r10
        movq	[%rbp+48], r11
        movq	r13, r14
        movq	r10, r14
        movq	r11, r14
        ; A[7] x A[0]
        mulxq	rcx, rax, [%r8+56]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[8] x A[0]
        mulxq	rcx, rax, [%r8+64]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[9] x A[0]
        mulxq	rcx, rax, [%r8+72]
        adcxq	r10, rax
        adoxq	r11, rcx
        movq	[%rbp+56], r12
        movq	[%rbp+64], r13
        movq	[%rbp+72], r10
        movq	r12, r14
        movq	r13, r14
        movq	r10, r14
        ; A[10] x A[0]
        mulxq	rcx, rax, [%r8+80]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[11] x A[0]
        mulxq	rcx, rax, [%r8+88]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[12] x A[0]
        mulxq	rcx, rax, [%r8+96]
        adcxq	r13, rax
        adoxq	r10, rcx
        movq	[%rbp+80], r11
        movq	[%rbp+88], r12
        movq	[%rbp+96], r13
        movq	r11, r14
        movq	r12, r14
        movq	r13, r14
        ; A[13] x A[0]
        mulxq	rcx, rax, [%r8+104]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[14] x A[0]
        mulxq	rcx, rax, [%r8+112]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[15] x A[0]
        mulxq	rcx, rax, [%r8+120]
        adcxq	r12, rax
        adoxq	r13, rcx
        movq	[%rbp+104], r10
        movq	[%rbp+112], r11
        movq	[%rbp+120], r12
        ;  Carry
        adcxq	r13, r14
        movq	r15, r14
        adcxq	r15, r14
        adoxq	r15, r14
        movq	[%r9+128], r13
        ; Diagonal 2
        movq	r13, [%rbp+24]
        movq	r10, [%rbp+32]
        movq	r11, [%rbp+40]
        movq	r12, [%rbp+48]
        ; A[2] x A[1]
        movq	rdx, [%r8+8]
        mulxq	rcx, rax, [%r8+16]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[3] x A[1]
        mulxq	rcx, rax, [%r8+24]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[4] x A[1]
        mulxq	rcx, rax, [%r8+32]
        adcxq	r11, rax
        adoxq	r12, rcx
        movq	[%rbp+24], r13
        movq	[%rbp+32], r10
        movq	[%rbp+40], r11
        movq	r13, [%rbp+56]
        movq	r10, [%rbp+64]
        movq	r11, [%rbp+72]
        ; A[5] x A[1]
        mulxq	rcx, rax, [%r8+40]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[6] x A[1]
        mulxq	rcx, rax, [%r8+48]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[7] x A[1]
        mulxq	rcx, rax, [%r8+56]
        adcxq	r10, rax
        adoxq	r11, rcx
        movq	[%rbp+48], r12
        movq	[%rbp+56], r13
        movq	[%rbp+64], r10
        movq	r12, [%rbp+80]
        movq	r13, [%rbp+88]
        movq	r10, [%rbp+96]
        ; A[8] x A[1]
        mulxq	rcx, rax, [%r8+64]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[9] x A[1]
        mulxq	rcx, rax, [%r8+72]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[10] x A[1]
        mulxq	rcx, rax, [%r8+80]
        adcxq	r13, rax
        adoxq	r10, rcx
        movq	[%rbp+72], r11
        movq	[%rbp+80], r12
        movq	[%rbp+88], r13
        movq	r11, [%rbp+104]
        movq	r12, [%rbp+112]
        movq	r13, [%rbp+120]
        ; A[11] x A[1]
        mulxq	rcx, rax, [%r8+88]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[12] x A[1]
        mulxq	rcx, rax, [%r8+96]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[13] x A[1]
        mulxq	rcx, rax, [%r8+104]
        adcxq	r12, rax
        adoxq	r13, rcx
        movq	[%rbp+96], r10
        movq	[%rbp+104], r11
        movq	[%rbp+112], r12
        movq	r10, [%r9+128]
        movq	r11, r14
        movq	r12, r14
        ; A[14] x A[1]
        mulxq	rcx, rax, [%r8+112]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[15] x A[1]
        mulxq	rcx, rax, [%r8+120]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[15] x A[2]
        movq	rdx, [%r8+16]
        mulxq	rcx, rax, [%r8+120]
        adcxq	r11, rax
        adoxq	r12, rcx
        movq	[%rbp+120], r13
        movq	[%r9+128], r10
        movq	[%r9+136], r11
        ;  Carry
        adcxq	r12, r15
        movq	r15, r14
        adcxq	r15, r14
        adoxq	r15, r14
        movq	[%r9+144], r12
        ; Diagonal 3
        movq	r12, [%rbp+40]
        movq	r13, [%rbp+48]
        movq	r10, [%rbp+56]
        movq	r11, [%rbp+64]
        ; A[3] x A[2]
        mulxq	rcx, rax, [%r8+24]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[4] x A[2]
        mulxq	rcx, rax, [%r8+32]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[5] x A[2]
        mulxq	rcx, rax, [%r8+40]
        adcxq	r10, rax
        adoxq	r11, rcx
        movq	[%rbp+40], r12
        movq	[%rbp+48], r13
        movq	[%rbp+56], r10
        movq	r12, [%rbp+72]
        movq	r13, [%rbp+80]
        movq	r10, [%rbp+88]
        ; A[6] x A[2]
        mulxq	rcx, rax, [%r8+48]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[7] x A[2]
        mulxq	rcx, rax, [%r8+56]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[8] x A[2]
        mulxq	rcx, rax, [%r8+64]
        adcxq	r13, rax
        adoxq	r10, rcx
        movq	[%rbp+64], r11
        movq	[%rbp+72], r12
        movq	[%rbp+80], r13
        movq	r11, [%rbp+96]
        movq	r12, [%rbp+104]
        movq	r13, [%rbp+112]
        ; A[9] x A[2]
        mulxq	rcx, rax, [%r8+72]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[10] x A[2]
        mulxq	rcx, rax, [%r8+80]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[11] x A[2]
        mulxq	rcx, rax, [%r8+88]
        adcxq	r12, rax
        adoxq	r13, rcx
        movq	[%rbp+88], r10
        movq	[%rbp+96], r11
        movq	[%rbp+104], r12
        movq	r10, [%rbp+120]
        movq	r11, [%r9+128]
        movq	r12, [%r9+136]
        ; A[12] x A[2]
        mulxq	rcx, rax, [%r8+96]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[13] x A[2]
        mulxq	rcx, rax, [%r8+104]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[14] x A[2]
        mulxq	rcx, rax, [%r8+112]
        adcxq	r11, rax
        adoxq	r12, rcx
        movq	[%rbp+112], r13
        movq	[%rbp+120], r10
        movq	[%r9+128], r11
        movq	r13, [%r9+144]
        movq	r10, r14
        movq	r11, r14
        ; A[14] x A[3]
        movq	rdx, [%r8+112]
        mulxq	rcx, rax, [%r8+24]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[14] x A[4]
        mulxq	rcx, rax, [%r8+32]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[14] x A[5]
        mulxq	rcx, rax, [%r8+40]
        adcxq	r10, rax
        adoxq	r11, rcx
        movq	[%r9+136], r12
        movq	[%r9+144], r13
        movq	[%r9+152], r10
        ;  Carry
        adcxq	r11, r15
        movq	r15, r14
        adcxq	r15, r14
        adoxq	r15, r14
        movq	[%r9+160], r11
        ; Diagonal 4
        movq	r11, [%rbp+56]
        movq	r12, [%rbp+64]
        movq	r13, [%rbp+72]
        movq	r10, [%rbp+80]
        ; A[4] x A[3]
        movq	rdx, [%r8+24]
        mulxq	rcx, rax, [%r8+32]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[5] x A[3]
        mulxq	rcx, rax, [%r8+40]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[6] x A[3]
        mulxq	rcx, rax, [%r8+48]
        adcxq	r13, rax
        adoxq	r10, rcx
        movq	[%rbp+56], r11
        movq	[%rbp+64], r12
        movq	[%rbp+72], r13
        movq	r11, [%rbp+88]
        movq	r12, [%rbp+96]
        movq	r13, [%rbp+104]
        ; A[7] x A[3]
        mulxq	rcx, rax, [%r8+56]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[8] x A[3]
        mulxq	rcx, rax, [%r8+64]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[9] x A[3]
        mulxq	rcx, rax, [%r8+72]
        adcxq	r12, rax
        adoxq	r13, rcx
        movq	[%rbp+80], r10
        movq	[%rbp+88], r11
        movq	[%rbp+96], r12
        movq	r10, [%rbp+112]
        movq	r11, [%rbp+120]
        movq	r12, [%r9+128]
        ; A[10] x A[3]
        mulxq	rcx, rax, [%r8+80]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[11] x A[3]
        mulxq	rcx, rax, [%r8+88]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[12] x A[3]
        mulxq	rcx, rax, [%r8+96]
        adcxq	r11, rax
        adoxq	r12, rcx
        movq	[%rbp+104], r13
        movq	[%rbp+112], r10
        movq	[%rbp+120], r11
        movq	r13, [%r9+136]
        movq	r10, [%r9+144]
        movq	r11, [%r9+152]
        ; A[13] x A[3]
        mulxq	rcx, rax, [%r8+104]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[13] x A[4]
        movq	rdx, [%r8+104]
        mulxq	rcx, rax, [%r8+32]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[13] x A[5]
        mulxq	rcx, rax, [%r8+40]
        adcxq	r10, rax
        adoxq	r11, rcx
        movq	[%r9+128], r12
        movq	[%r9+136], r13
        movq	[%r9+144], r10
        movq	r12, [%r9+160]
        movq	r13, r14
        movq	r10, r14
        ; A[13] x A[6]
        mulxq	rcx, rax, [%r8+48]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[13] x A[7]
        mulxq	rcx, rax, [%r8+56]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[13] x A[8]
        mulxq	rcx, rax, [%r8+64]
        adcxq	r13, rax
        adoxq	r10, rcx
        movq	[%r9+152], r11
        movq	[%r9+160], r12
        movq	[%r9+168], r13
        ;  Carry
        adcxq	r10, r15
        movq	r15, r14
        adcxq	r15, r14
        adoxq	r15, r14
        movq	[%r9+176], r10
        ; Diagonal 5
        movq	r10, [%rbp+72]
        movq	r11, [%rbp+80]
        movq	r12, [%rbp+88]
        movq	r13, [%rbp+96]
        ; A[5] x A[4]
        movq	rdx, [%r8+32]
        mulxq	rcx, rax, [%r8+40]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[6] x A[4]
        mulxq	rcx, rax, [%r8+48]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[7] x A[4]
        mulxq	rcx, rax, [%r8+56]
        adcxq	r12, rax
        adoxq	r13, rcx
        movq	[%rbp+72], r10
        movq	[%rbp+80], r11
        movq	[%rbp+88], r12
        movq	r10, [%rbp+104]
        movq	r11, [%rbp+112]
        movq	r12, [%rbp+120]
        ; A[8] x A[4]
        mulxq	rcx, rax, [%r8+64]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[9] x A[4]
        mulxq	rcx, rax, [%r8+72]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[10] x A[4]
        mulxq	rcx, rax, [%r8+80]
        adcxq	r11, rax
        adoxq	r12, rcx
        movq	[%rbp+96], r13
        movq	[%rbp+104], r10
        movq	[%rbp+112], r11
        movq	r13, [%r9+128]
        movq	r10, [%r9+136]
        movq	r11, [%r9+144]
        ; A[11] x A[4]
        mulxq	rcx, rax, [%r8+88]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[12] x A[4]
        mulxq	rcx, rax, [%r8+96]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[12] x A[5]
        movq	rdx, [%r8+96]
        mulxq	rcx, rax, [%r8+40]
        adcxq	r10, rax
        adoxq	r11, rcx
        movq	[%rbp+120], r12
        movq	[%r9+128], r13
        movq	[%r9+136], r10
        movq	r12, [%r9+152]
        movq	r13, [%r9+160]
        movq	r10, [%r9+168]
        ; A[12] x A[6]
        mulxq	rcx, rax, [%r8+48]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[12] x A[7]
        mulxq	rcx, rax, [%r8+56]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[12] x A[8]
        mulxq	rcx, rax, [%r8+64]
        adcxq	r13, rax
        adoxq	r10, rcx
        movq	[%r9+144], r11
        movq	[%r9+152], r12
        movq	[%r9+160], r13
        movq	r11, [%r9+176]
        movq	r12, r14
        movq	r13, r14
        ; A[12] x A[9]
        mulxq	rcx, rax, [%r8+72]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[12] x A[10]
        mulxq	rcx, rax, [%r8+80]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[12] x A[11]
        mulxq	rcx, rax, [%r8+88]
        adcxq	r12, rax
        adoxq	r13, rcx
        movq	[%r9+168], r10
        movq	[%r9+176], r11
        movq	[%r9+184], r12
        ;  Carry
        adcxq	r13, r15
        movq	r15, r14
        adcxq	r15, r14
        adoxq	r15, r14
        movq	[%r9+192], r13
        ; Diagonal 6
        movq	r13, [%rbp+88]
        movq	r10, [%rbp+96]
        movq	r11, [%rbp+104]
        movq	r12, [%rbp+112]
        ; A[6] x A[5]
        movq	rdx, [%r8+40]
        mulxq	rcx, rax, [%r8+48]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[7] x A[5]
        mulxq	rcx, rax, [%r8+56]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[8] x A[5]
        mulxq	rcx, rax, [%r8+64]
        adcxq	r11, rax
        adoxq	r12, rcx
        movq	[%rbp+88], r13
        movq	[%rbp+96], r10
        movq	[%rbp+104], r11
        movq	r13, [%rbp+120]
        movq	r10, [%r9+128]
        movq	r11, [%r9+136]
        ; A[9] x A[5]
        mulxq	rcx, rax, [%r8+72]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[10] x A[5]
        mulxq	rcx, rax, [%r8+80]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[11] x A[5]
        mulxq	rcx, rax, [%r8+88]
        adcxq	r10, rax
        adoxq	r11, rcx
        movq	[%rbp+112], r12
        movq	[%rbp+120], r13
        movq	[%r9+128], r10
        movq	r12, [%r9+144]
        movq	r13, [%r9+152]
        movq	r10, [%r9+160]
        ; A[11] x A[6]
        movq	rdx, [%r8+88]
        mulxq	rcx, rax, [%r8+48]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[11] x A[7]
        mulxq	rcx, rax, [%r8+56]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[11] x A[8]
        mulxq	rcx, rax, [%r8+64]
        adcxq	r13, rax
        adoxq	r10, rcx
        movq	[%r9+136], r11
        movq	[%r9+144], r12
        movq	[%r9+152], r13
        movq	r11, [%r9+168]
        movq	r12, [%r9+176]
        movq	r13, [%r9+184]
        ; A[11] x A[9]
        mulxq	rcx, rax, [%r8+72]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[11] x A[10]
        mulxq	rcx, rax, [%r8+80]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[13] x A[9]
        movq	rdx, [%r8+104]
        mulxq	rcx, rax, [%r8+72]
        adcxq	r12, rax
        adoxq	r13, rcx
        movq	[%r9+160], r10
        movq	[%r9+168], r11
        movq	[%r9+176], r12
        movq	r10, [%r9+192]
        movq	r11, r14
        movq	r12, r14
        ; A[13] x A[10]
        mulxq	rcx, rax, [%r8+80]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[13] x A[11]
        mulxq	rcx, rax, [%r8+88]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[13] x A[12]
        mulxq	rcx, rax, [%r8+96]
        adcxq	r11, rax
        adoxq	r12, rcx
        movq	[%r9+184], r13
        movq	[%r9+192], r10
        movq	[%r9+200], r11
        ;  Carry
        adcxq	r12, r15
        movq	r15, r14
        adcxq	r15, r14
        adoxq	r15, r14
        movq	[%r9+208], r12
        ; Diagonal 7
        movq	r12, [%rbp+104]
        movq	r13, [%rbp+112]
        movq	r10, [%rbp+120]
        movq	r11, [%r9+128]
        ; A[7] x A[6]
        movq	rdx, [%r8+48]
        mulxq	rcx, rax, [%r8+56]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[8] x A[6]
        mulxq	rcx, rax, [%r8+64]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[9] x A[6]
        mulxq	rcx, rax, [%r8+72]
        adcxq	r10, rax
        adoxq	r11, rcx
        movq	[%rbp+104], r12
        movq	[%rbp+112], r13
        movq	[%rbp+120], r10
        movq	r12, [%r9+136]
        movq	r13, [%r9+144]
        movq	r10, [%r9+152]
        ; A[10] x A[6]
        mulxq	rcx, rax, [%r8+80]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[10] x A[7]
        movq	rdx, [%r8+80]
        mulxq	rcx, rax, [%r8+56]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[10] x A[8]
        mulxq	rcx, rax, [%r8+64]
        adcxq	r13, rax
        adoxq	r10, rcx
        movq	[%r9+128], r11
        movq	[%r9+136], r12
        movq	[%r9+144], r13
        movq	r11, [%r9+160]
        movq	r12, [%r9+168]
        movq	r13, [%r9+176]
        ; A[10] x A[9]
        mulxq	rcx, rax, [%r8+72]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[14] x A[6]
        movq	rdx, [%r8+112]
        mulxq	rcx, rax, [%r8+48]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[14] x A[7]
        mulxq	rcx, rax, [%r8+56]
        adcxq	r12, rax
        adoxq	r13, rcx
        movq	[%r9+152], r10
        movq	[%r9+160], r11
        movq	[%r9+168], r12
        movq	r10, [%r9+184]
        movq	r11, [%r9+192]
        movq	r12, [%r9+200]
        ; A[14] x A[8]
        mulxq	rcx, rax, [%r8+64]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[14] x A[9]
        mulxq	rcx, rax, [%r8+72]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[14] x A[10]
        mulxq	rcx, rax, [%r8+80]
        adcxq	r11, rax
        adoxq	r12, rcx
        movq	[%r9+176], r13
        movq	[%r9+184], r10
        movq	[%r9+192], r11
        movq	r13, [%r9+208]
        movq	r10, r14
        movq	r11, r14
        ; A[14] x A[11]
        mulxq	rcx, rax, [%r8+88]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[14] x A[12]
        mulxq	rcx, rax, [%r8+96]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[14] x A[13]
        mulxq	rcx, rax, [%r8+104]
        adcxq	r10, rax
        adoxq	r11, rcx
        movq	[%r9+200], r12
        movq	[%r9+208], r13
        movq	[%r9+216], r10
        ;  Carry
        adcxq	r11, r15
        movq	r15, r14
        adcxq	r15, r14
        adoxq	r15, r14
        movq	[%r9+224], r11
        ; Diagonal 8
        movq	r11, [%rbp+120]
        movq	r12, [%r9+128]
        movq	r13, [%r9+136]
        movq	r10, [%r9+144]
        ; A[8] x A[7]
        movq	rdx, [%r8+56]
        mulxq	rcx, rax, [%r8+64]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[9] x A[7]
        mulxq	rcx, rax, [%r8+72]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[9] x A[8]
        movq	rdx, [%r8+64]
        mulxq	rcx, rax, [%r8+72]
        adcxq	r13, rax
        adoxq	r10, rcx
        movq	[%rbp+120], r11
        movq	[%r9+128], r12
        movq	[%r9+136], r13
        movq	r11, [%r9+152]
        movq	r12, [%r9+160]
        movq	r13, [%r9+168]
        ; A[15] x A[3]
        movq	rdx, [%r8+120]
        mulxq	rcx, rax, [%r8+24]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[15] x A[4]
        mulxq	rcx, rax, [%r8+32]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[15] x A[5]
        mulxq	rcx, rax, [%r8+40]
        adcxq	r12, rax
        adoxq	r13, rcx
        movq	[%r9+144], r10
        movq	[%r9+152], r11
        movq	[%r9+160], r12
        movq	r10, [%r9+176]
        movq	r11, [%r9+184]
        movq	r12, [%r9+192]
        ; A[15] x A[6]
        mulxq	rcx, rax, [%r8+48]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[15] x A[7]
        mulxq	rcx, rax, [%r8+56]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[15] x A[8]
        mulxq	rcx, rax, [%r8+64]
        adcxq	r11, rax
        adoxq	r12, rcx
        movq	[%r9+168], r13
        movq	[%r9+176], r10
        movq	[%r9+184], r11
        movq	r13, [%r9+200]
        movq	r10, [%r9+208]
        movq	r11, [%r9+216]
        ; A[15] x A[9]
        mulxq	rcx, rax, [%r8+72]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[15] x A[10]
        mulxq	rcx, rax, [%r8+80]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[15] x A[11]
        mulxq	rcx, rax, [%r8+88]
        adcxq	r10, rax
        adoxq	r11, rcx
        movq	[%r9+192], r12
        movq	[%r9+200], r13
        movq	[%r9+208], r10
        movq	r12, [%r9+224]
        movq	r13, r14
        movq	r10, r14
        ; A[15] x A[12]
        mulxq	rcx, rax, [%r8+96]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[15] x A[13]
        mulxq	rcx, rax, [%r8+104]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[15] x A[14]
        mulxq	rcx, rax, [%r8+112]
        adcxq	r13, rax
        adoxq	r10, rcx
        movq	[%r9+216], r11
        movq	[%r9+224], r12
        movq	[%r9+232], r13
        ;  Carry
        adcxq	r10, r15
        movq	r15, r14
        adcxq	r15, r14
        adoxq	r15, r14
        movq	[%r9+240], r10
        movq	[%r9+248], r15
        ; Double and Add in A[i] x A[i]
        movq	r11, [%rbp+8]
        ; A[0] x A[0]
        movq	rdx, [%r8]
        mulxq	rcx, rax, rdx
        movq	[%rbp], rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%rbp+8], r11
        movq	r10, [%rbp+16]
        movq	r11, [%rbp+24]
        ; A[1] x A[1]
        movq	rdx, [%r8+8]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%rbp+16], r10
        movq	[%rbp+24], r11
        movq	r10, [%rbp+32]
        movq	r11, [%rbp+40]
        ; A[2] x A[2]
        movq	rdx, [%r8+16]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%rbp+32], r10
        movq	[%rbp+40], r11
        movq	r10, [%rbp+48]
        movq	r11, [%rbp+56]
        ; A[3] x A[3]
        movq	rdx, [%r8+24]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%rbp+48], r10
        movq	[%rbp+56], r11
        movq	r10, [%rbp+64]
        movq	r11, [%rbp+72]
        ; A[4] x A[4]
        movq	rdx, [%r8+32]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%rbp+64], r10
        movq	[%rbp+72], r11
        movq	r10, [%rbp+80]
        movq	r11, [%rbp+88]
        ; A[5] x A[5]
        movq	rdx, [%r8+40]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%rbp+80], r10
        movq	[%rbp+88], r11
        movq	r10, [%rbp+96]
        movq	r11, [%rbp+104]
        ; A[6] x A[6]
        movq	rdx, [%r8+48]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%rbp+96], r10
        movq	[%rbp+104], r11
        movq	r10, [%rbp+112]
        movq	r11, [%rbp+120]
        ; A[7] x A[7]
        movq	rdx, [%r8+56]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%rbp+112], r10
        movq	[%rbp+120], r11
        movq	r10, [%r9+128]
        movq	r11, [%r9+136]
        ; A[8] x A[8]
        movq	rdx, [%r8+64]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%r9+128], r10
        movq	[%r9+136], r11
        movq	r10, [%r9+144]
        movq	r11, [%r9+152]
        ; A[9] x A[9]
        movq	rdx, [%r8+72]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%r9+144], r10
        movq	[%r9+152], r11
        movq	r10, [%r9+160]
        movq	r11, [%r9+168]
        ; A[10] x A[10]
        movq	rdx, [%r8+80]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%r9+160], r10
        movq	[%r9+168], r11
        movq	r10, [%r9+176]
        movq	r11, [%r9+184]
        ; A[11] x A[11]
        movq	rdx, [%r8+88]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%r9+176], r10
        movq	[%r9+184], r11
        movq	r10, [%r9+192]
        movq	r11, [%r9+200]
        ; A[12] x A[12]
        movq	rdx, [%r8+96]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%r9+192], r10
        movq	[%r9+200], r11
        movq	r10, [%r9+208]
        movq	r11, [%r9+216]
        ; A[13] x A[13]
        movq	rdx, [%r8+104]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%r9+208], r10
        movq	[%r9+216], r11
        movq	r10, [%r9+224]
        movq	r11, [%r9+232]
        ; A[14] x A[14]
        movq	rdx, [%r8+112]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%r9+224], r10
        movq	[%r9+232], r11
        movq	r10, [%r9+240]
        movq	r11, [%r9+248]
        ; A[15] x A[15]
        movq	rdx, [%r8+120]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%r9+240], r10
        movq	[%r9+248], r11
        cmpq	r8, r9
        jne	L_end_2048_sqr_avx2_16
        movq	r10, [%rbp]
        movq	r11, [%rbp+8]
        movq	r12, [%rbp+16]
        movq	r13, [%rbp+24]
        movq	[%r9], r10
        movq	[%r9+8], r11
        movq	[%r9+16], r12
        movq	[%r9+24], r13
        movq	r10, [%rbp+32]
        movq	r11, [%rbp+40]
        movq	r12, [%rbp+48]
        movq	r13, [%rbp+56]
        movq	[%r9+32], r10
        movq	[%r9+40], r11
        movq	[%r9+48], r12
        movq	[%r9+56], r13
        movq	r10, [%rbp+64]
        movq	r11, [%rbp+72]
        movq	r12, [%rbp+80]
        movq	r13, [%rbp+88]
        movq	[%r9+64], r10
        movq	[%r9+72], r11
        movq	[%r9+80], r12
        movq	[%r9+88], r13
        movq	r10, [%rbp+96]
        movq	r11, [%rbp+104]
        movq	r12, [%rbp+112]
        movq	r13, [%rbp+120]
        movq	[%r9+96], r10
        movq	[%r9+104], r11
        movq	[%r9+112], r12
        movq	[%r9+120], r13
L_end_2048_sqr_avx2_16:
        addq	rsp, 128
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rbp
        repz retq
sp_2048_sqr_avx2_16 ENDP
ENDIF
; /* Add b to a into r. (r = a + b)
;  *
;  * r  A single precision integer.
;  * a  A single precision integer.
;  * b  A single precision integer.
;  */
sp_2048_add_16 PROC
        xorq	rax, rax
        movq	r9, [%rdx]
        addq	r9, [%r8]
        movq	[%rcx], r9
        movq	r9, [%rdx+8]
        adcq	r9, [%r8+8]
        movq	[%rcx+8], r9
        movq	r9, [%rdx+16]
        adcq	r9, [%r8+16]
        movq	[%rcx+16], r9
        movq	r9, [%rdx+24]
        adcq	r9, [%r8+24]
        movq	[%rcx+24], r9
        movq	r9, [%rdx+32]
        adcq	r9, [%r8+32]
        movq	[%rcx+32], r9
        movq	r9, [%rdx+40]
        adcq	r9, [%r8+40]
        movq	[%rcx+40], r9
        movq	r9, [%rdx+48]
        adcq	r9, [%r8+48]
        movq	[%rcx+48], r9
        movq	r9, [%rdx+56]
        adcq	r9, [%r8+56]
        movq	[%rcx+56], r9
        movq	r9, [%rdx+64]
        adcq	r9, [%r8+64]
        movq	[%rcx+64], r9
        movq	r9, [%rdx+72]
        adcq	r9, [%r8+72]
        movq	[%rcx+72], r9
        movq	r9, [%rdx+80]
        adcq	r9, [%r8+80]
        movq	[%rcx+80], r9
        movq	r9, [%rdx+88]
        adcq	r9, [%r8+88]
        movq	[%rcx+88], r9
        movq	r9, [%rdx+96]
        adcq	r9, [%r8+96]
        movq	[%rcx+96], r9
        movq	r9, [%rdx+104]
        adcq	r9, [%r8+104]
        movq	[%rcx+104], r9
        movq	r9, [%rdx+112]
        adcq	r9, [%r8+112]
        movq	[%rcx+112], r9
        movq	r9, [%rdx+120]
        adcq	r9, [%r8+120]
        movq	[%rcx+120], r9
        adcq	rax, 0
        repz retq
sp_2048_add_16 ENDP
; /* Sub b from a into a. (a -= b)
;  *
;  * a  A single precision integer and result.
;  * b  A single precision integer.
;  */
sp_2048_sub_in_place_32 PROC
        xorq	rax, rax
        movq	r8, [%rcx]
        movq	r9, [%rcx+8]
        movq	r10, [%rdx]
        movq	r11, [%rdx+8]
        subq	r8, r10
        movq	r10, [%rdx+16]
        movq	[%rcx], r8
        movq	r8, [%rcx+16]
        sbbq	r9, r11
        movq	r11, [%rdx+24]
        movq	[%rcx+8], r9
        movq	r9, [%rcx+24]
        sbbq	r8, r10
        movq	r10, [%rdx+32]
        movq	[%rcx+16], r8
        movq	r8, [%rcx+32]
        sbbq	r9, r11
        movq	r11, [%rdx+40]
        movq	[%rcx+24], r9
        movq	r9, [%rcx+40]
        sbbq	r8, r10
        movq	r10, [%rdx+48]
        movq	[%rcx+32], r8
        movq	r8, [%rcx+48]
        sbbq	r9, r11
        movq	r11, [%rdx+56]
        movq	[%rcx+40], r9
        movq	r9, [%rcx+56]
        sbbq	r8, r10
        movq	r10, [%rdx+64]
        movq	[%rcx+48], r8
        movq	r8, [%rcx+64]
        sbbq	r9, r11
        movq	r11, [%rdx+72]
        movq	[%rcx+56], r9
        movq	r9, [%rcx+72]
        sbbq	r8, r10
        movq	r10, [%rdx+80]
        movq	[%rcx+64], r8
        movq	r8, [%rcx+80]
        sbbq	r9, r11
        movq	r11, [%rdx+88]
        movq	[%rcx+72], r9
        movq	r9, [%rcx+88]
        sbbq	r8, r10
        movq	r10, [%rdx+96]
        movq	[%rcx+80], r8
        movq	r8, [%rcx+96]
        sbbq	r9, r11
        movq	r11, [%rdx+104]
        movq	[%rcx+88], r9
        movq	r9, [%rcx+104]
        sbbq	r8, r10
        movq	r10, [%rdx+112]
        movq	[%rcx+96], r8
        movq	r8, [%rcx+112]
        sbbq	r9, r11
        movq	r11, [%rdx+120]
        movq	[%rcx+104], r9
        movq	r9, [%rcx+120]
        sbbq	r8, r10
        movq	r10, [%rdx+128]
        movq	[%rcx+112], r8
        movq	r8, [%rcx+128]
        sbbq	r9, r11
        movq	r11, [%rdx+136]
        movq	[%rcx+120], r9
        movq	r9, [%rcx+136]
        sbbq	r8, r10
        movq	r10, [%rdx+144]
        movq	[%rcx+128], r8
        movq	r8, [%rcx+144]
        sbbq	r9, r11
        movq	r11, [%rdx+152]
        movq	[%rcx+136], r9
        movq	r9, [%rcx+152]
        sbbq	r8, r10
        movq	r10, [%rdx+160]
        movq	[%rcx+144], r8
        movq	r8, [%rcx+160]
        sbbq	r9, r11
        movq	r11, [%rdx+168]
        movq	[%rcx+152], r9
        movq	r9, [%rcx+168]
        sbbq	r8, r10
        movq	r10, [%rdx+176]
        movq	[%rcx+160], r8
        movq	r8, [%rcx+176]
        sbbq	r9, r11
        movq	r11, [%rdx+184]
        movq	[%rcx+168], r9
        movq	r9, [%rcx+184]
        sbbq	r8, r10
        movq	r10, [%rdx+192]
        movq	[%rcx+176], r8
        movq	r8, [%rcx+192]
        sbbq	r9, r11
        movq	r11, [%rdx+200]
        movq	[%rcx+184], r9
        movq	r9, [%rcx+200]
        sbbq	r8, r10
        movq	r10, [%rdx+208]
        movq	[%rcx+192], r8
        movq	r8, [%rcx+208]
        sbbq	r9, r11
        movq	r11, [%rdx+216]
        movq	[%rcx+200], r9
        movq	r9, [%rcx+216]
        sbbq	r8, r10
        movq	r10, [%rdx+224]
        movq	[%rcx+208], r8
        movq	r8, [%rcx+224]
        sbbq	r9, r11
        movq	r11, [%rdx+232]
        movq	[%rcx+216], r9
        movq	r9, [%rcx+232]
        sbbq	r8, r10
        movq	r10, [%rdx+240]
        movq	[%rcx+224], r8
        movq	r8, [%rcx+240]
        sbbq	r9, r11
        movq	r11, [%rdx+248]
        movq	[%rcx+232], r9
        movq	r9, [%rcx+248]
        sbbq	r8, r10
        movq	[%rcx+240], r8
        sbbq	r9, r11
        movq	[%rcx+248], r9
        sbbq	rax, 0
        repz retq
sp_2048_sub_in_place_32 ENDP
; /* Add b to a into r. (r = a + b)
;  *
;  * r  A single precision integer.
;  * a  A single precision integer.
;  * b  A single precision integer.
;  */
sp_2048_add_32 PROC
        xorq	rax, rax
        movq	r9, [%rdx]
        addq	r9, [%r8]
        movq	[%rcx], r9
        movq	r9, [%rdx+8]
        adcq	r9, [%r8+8]
        movq	[%rcx+8], r9
        movq	r9, [%rdx+16]
        adcq	r9, [%r8+16]
        movq	[%rcx+16], r9
        movq	r9, [%rdx+24]
        adcq	r9, [%r8+24]
        movq	[%rcx+24], r9
        movq	r9, [%rdx+32]
        adcq	r9, [%r8+32]
        movq	[%rcx+32], r9
        movq	r9, [%rdx+40]
        adcq	r9, [%r8+40]
        movq	[%rcx+40], r9
        movq	r9, [%rdx+48]
        adcq	r9, [%r8+48]
        movq	[%rcx+48], r9
        movq	r9, [%rdx+56]
        adcq	r9, [%r8+56]
        movq	[%rcx+56], r9
        movq	r9, [%rdx+64]
        adcq	r9, [%r8+64]
        movq	[%rcx+64], r9
        movq	r9, [%rdx+72]
        adcq	r9, [%r8+72]
        movq	[%rcx+72], r9
        movq	r9, [%rdx+80]
        adcq	r9, [%r8+80]
        movq	[%rcx+80], r9
        movq	r9, [%rdx+88]
        adcq	r9, [%r8+88]
        movq	[%rcx+88], r9
        movq	r9, [%rdx+96]
        adcq	r9, [%r8+96]
        movq	[%rcx+96], r9
        movq	r9, [%rdx+104]
        adcq	r9, [%r8+104]
        movq	[%rcx+104], r9
        movq	r9, [%rdx+112]
        adcq	r9, [%r8+112]
        movq	[%rcx+112], r9
        movq	r9, [%rdx+120]
        adcq	r9, [%r8+120]
        movq	[%rcx+120], r9
        movq	r9, [%rdx+128]
        adcq	r9, [%r8+128]
        movq	[%rcx+128], r9
        movq	r9, [%rdx+136]
        adcq	r9, [%r8+136]
        movq	[%rcx+136], r9
        movq	r9, [%rdx+144]
        adcq	r9, [%r8+144]
        movq	[%rcx+144], r9
        movq	r9, [%rdx+152]
        adcq	r9, [%r8+152]
        movq	[%rcx+152], r9
        movq	r9, [%rdx+160]
        adcq	r9, [%r8+160]
        movq	[%rcx+160], r9
        movq	r9, [%rdx+168]
        adcq	r9, [%r8+168]
        movq	[%rcx+168], r9
        movq	r9, [%rdx+176]
        adcq	r9, [%r8+176]
        movq	[%rcx+176], r9
        movq	r9, [%rdx+184]
        adcq	r9, [%r8+184]
        movq	[%rcx+184], r9
        movq	r9, [%rdx+192]
        adcq	r9, [%r8+192]
        movq	[%rcx+192], r9
        movq	r9, [%rdx+200]
        adcq	r9, [%r8+200]
        movq	[%rcx+200], r9
        movq	r9, [%rdx+208]
        adcq	r9, [%r8+208]
        movq	[%rcx+208], r9
        movq	r9, [%rdx+216]
        adcq	r9, [%r8+216]
        movq	[%rcx+216], r9
        movq	r9, [%rdx+224]
        adcq	r9, [%r8+224]
        movq	[%rcx+224], r9
        movq	r9, [%rdx+232]
        adcq	r9, [%r8+232]
        movq	[%rcx+232], r9
        movq	r9, [%rdx+240]
        adcq	r9, [%r8+240]
        movq	[%rcx+240], r9
        movq	r9, [%rdx+248]
        adcq	r9, [%r8+248]
        movq	[%rcx+248], r9
        adcq	rax, 0
        repz retq
sp_2048_add_32 ENDP
; /* Mul a by digit b into r. (r = a * b)
;  *
;  * r  A single precision integer.
;  * a  A single precision integer.
;  * b  A single precision digit.
;  */
sp_2048_mul_d_32 PROC
        movq	rcx, rdx
        movq	r9, rcx
        push	r12
        ; A[0] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx]
        movq	r10, rax
        movq	r11, rdx
        movq	[%r9], r10
        ; A[1] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+8]
        addq	r11, rax
        movq	[%r9+8], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[2] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+16]
        addq	r12, rax
        movq	[%r9+16], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; A[3] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx+24]
        addq	r10, rax
        movq	[%r9+24], r10
        adcq	r11, rdx
        adcq	r12, 0
        ; A[4] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+32]
        addq	r11, rax
        movq	[%r9+32], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[5] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+40]
        addq	r12, rax
        movq	[%r9+40], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; A[6] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx+48]
        addq	r10, rax
        movq	[%r9+48], r10
        adcq	r11, rdx
        adcq	r12, 0
        ; A[7] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+56]
        addq	r11, rax
        movq	[%r9+56], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[8] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+64]
        addq	r12, rax
        movq	[%r9+64], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; A[9] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx+72]
        addq	r10, rax
        movq	[%r9+72], r10
        adcq	r11, rdx
        adcq	r12, 0
        ; A[10] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+80]
        addq	r11, rax
        movq	[%r9+80], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[11] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+88]
        addq	r12, rax
        movq	[%r9+88], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; A[12] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx+96]
        addq	r10, rax
        movq	[%r9+96], r10
        adcq	r11, rdx
        adcq	r12, 0
        ; A[13] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+104]
        addq	r11, rax
        movq	[%r9+104], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[14] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+112]
        addq	r12, rax
        movq	[%r9+112], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; A[15] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx+120]
        addq	r10, rax
        movq	[%r9+120], r10
        adcq	r11, rdx
        adcq	r12, 0
        ; A[16] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+128]
        addq	r11, rax
        movq	[%r9+128], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[17] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+136]
        addq	r12, rax
        movq	[%r9+136], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; A[18] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx+144]
        addq	r10, rax
        movq	[%r9+144], r10
        adcq	r11, rdx
        adcq	r12, 0
        ; A[19] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+152]
        addq	r11, rax
        movq	[%r9+152], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[20] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+160]
        addq	r12, rax
        movq	[%r9+160], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; A[21] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx+168]
        addq	r10, rax
        movq	[%r9+168], r10
        adcq	r11, rdx
        adcq	r12, 0
        ; A[22] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+176]
        addq	r11, rax
        movq	[%r9+176], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[23] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+184]
        addq	r12, rax
        movq	[%r9+184], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; A[24] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx+192]
        addq	r10, rax
        movq	[%r9+192], r10
        adcq	r11, rdx
        adcq	r12, 0
        ; A[25] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+200]
        addq	r11, rax
        movq	[%r9+200], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[26] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+208]
        addq	r12, rax
        movq	[%r9+208], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; A[27] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx+216]
        addq	r10, rax
        movq	[%r9+216], r10
        adcq	r11, rdx
        adcq	r12, 0
        ; A[28] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+224]
        addq	r11, rax
        movq	[%r9+224], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[29] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+232]
        addq	r12, rax
        movq	[%r9+232], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; A[30] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx+240]
        addq	r10, rax
        movq	[%r9+240], r10
        adcq	r11, rdx
        adcq	r12, 0
        ; # A[31] * B
        movq	rax, r8
        mulq	[%rcx+248]
        addq	r11, rax
        adcq	r12, rdx
        movq	[%r9+248], r11
        movq	[%r9+256], r12
        pop	r12
        repz retq
sp_2048_mul_d_32 ENDP
; /* Sub b from a into a. (a -= b)
;  *
;  * a  A single precision integer and result.
;  * b  A single precision integer.
;  */
sp_2048_sub_in_place_16 PROC
        xorq	rax, rax
        movq	r8, [%rcx]
        movq	r9, [%rcx+8]
        movq	r10, [%rdx]
        movq	r11, [%rdx+8]
        subq	r8, r10
        movq	r10, [%rdx+16]
        movq	[%rcx], r8
        movq	r8, [%rcx+16]
        sbbq	r9, r11
        movq	r11, [%rdx+24]
        movq	[%rcx+8], r9
        movq	r9, [%rcx+24]
        sbbq	r8, r10
        movq	r10, [%rdx+32]
        movq	[%rcx+16], r8
        movq	r8, [%rcx+32]
        sbbq	r9, r11
        movq	r11, [%rdx+40]
        movq	[%rcx+24], r9
        movq	r9, [%rcx+40]
        sbbq	r8, r10
        movq	r10, [%rdx+48]
        movq	[%rcx+32], r8
        movq	r8, [%rcx+48]
        sbbq	r9, r11
        movq	r11, [%rdx+56]
        movq	[%rcx+40], r9
        movq	r9, [%rcx+56]
        sbbq	r8, r10
        movq	r10, [%rdx+64]
        movq	[%rcx+48], r8
        movq	r8, [%rcx+64]
        sbbq	r9, r11
        movq	r11, [%rdx+72]
        movq	[%rcx+56], r9
        movq	r9, [%rcx+72]
        sbbq	r8, r10
        movq	r10, [%rdx+80]
        movq	[%rcx+64], r8
        movq	r8, [%rcx+80]
        sbbq	r9, r11
        movq	r11, [%rdx+88]
        movq	[%rcx+72], r9
        movq	r9, [%rcx+88]
        sbbq	r8, r10
        movq	r10, [%rdx+96]
        movq	[%rcx+80], r8
        movq	r8, [%rcx+96]
        sbbq	r9, r11
        movq	r11, [%rdx+104]
        movq	[%rcx+88], r9
        movq	r9, [%rcx+104]
        sbbq	r8, r10
        movq	r10, [%rdx+112]
        movq	[%rcx+96], r8
        movq	r8, [%rcx+112]
        sbbq	r9, r11
        movq	r11, [%rdx+120]
        movq	[%rcx+104], r9
        movq	r9, [%rcx+120]
        sbbq	r8, r10
        movq	[%rcx+112], r8
        sbbq	r9, r11
        movq	[%rcx+120], r9
        sbbq	rax, 0
        repz retq
sp_2048_sub_in_place_16 ENDP
; /* Conditionally subtract b from a using the mask m.
;  * m is -1 to subtract and 0 when not copying.
;  *
;  * r  A single precision number representing condition subtract result.
;  * a  A single precision number to subtract from.
;  * b  A single precision number to subtract.
;  * m  Mask value to apply.
;  */
sp_2048_cond_sub_16 PROC
        subq	rsp, 128
        movq	rax, 0
        movq	r10, [%r8]
        movq	r11, [%r8+8]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp], r10
        movq	[%rsp+8], r11
        movq	r10, [%r8+16]
        movq	r11, [%r8+24]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+16], r10
        movq	[%rsp+24], r11
        movq	r10, [%r8+32]
        movq	r11, [%r8+40]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+32], r10
        movq	[%rsp+40], r11
        movq	r10, [%r8+48]
        movq	r11, [%r8+56]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+48], r10
        movq	[%rsp+56], r11
        movq	r10, [%r8+64]
        movq	r11, [%r8+72]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+64], r10
        movq	[%rsp+72], r11
        movq	r10, [%r8+80]
        movq	r11, [%r8+88]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+80], r10
        movq	[%rsp+88], r11
        movq	r10, [%r8+96]
        movq	r11, [%r8+104]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+96], r10
        movq	[%rsp+104], r11
        movq	r10, [%r8+112]
        movq	r11, [%r8+120]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+112], r10
        movq	[%rsp+120], r11
        movq	r10, [%rdx]
        movq	r8, [%rsp]
        subq	r10, r8
        movq	r11, [%rdx+8]
        movq	r8, [%rsp+8]
        sbbq	r11, r8
        movq	[%rcx], r10
        movq	r10, [%rdx+16]
        movq	r8, [%rsp+16]
        sbbq	r10, r8
        movq	[%rcx+8], r11
        movq	r11, [%rdx+24]
        movq	r8, [%rsp+24]
        sbbq	r11, r8
        movq	[%rcx+16], r10
        movq	r10, [%rdx+32]
        movq	r8, [%rsp+32]
        sbbq	r10, r8
        movq	[%rcx+24], r11
        movq	r11, [%rdx+40]
        movq	r8, [%rsp+40]
        sbbq	r11, r8
        movq	[%rcx+32], r10
        movq	r10, [%rdx+48]
        movq	r8, [%rsp+48]
        sbbq	r10, r8
        movq	[%rcx+40], r11
        movq	r11, [%rdx+56]
        movq	r8, [%rsp+56]
        sbbq	r11, r8
        movq	[%rcx+48], r10
        movq	r10, [%rdx+64]
        movq	r8, [%rsp+64]
        sbbq	r10, r8
        movq	[%rcx+56], r11
        movq	r11, [%rdx+72]
        movq	r8, [%rsp+72]
        sbbq	r11, r8
        movq	[%rcx+64], r10
        movq	r10, [%rdx+80]
        movq	r8, [%rsp+80]
        sbbq	r10, r8
        movq	[%rcx+72], r11
        movq	r11, [%rdx+88]
        movq	r8, [%rsp+88]
        sbbq	r11, r8
        movq	[%rcx+80], r10
        movq	r10, [%rdx+96]
        movq	r8, [%rsp+96]
        sbbq	r10, r8
        movq	[%rcx+88], r11
        movq	r11, [%rdx+104]
        movq	r8, [%rsp+104]
        sbbq	r11, r8
        movq	[%rcx+96], r10
        movq	r10, [%rdx+112]
        movq	r8, [%rsp+112]
        sbbq	r10, r8
        movq	[%rcx+104], r11
        movq	r11, [%rdx+120]
        movq	r8, [%rsp+120]
        sbbq	r11, r8
        movq	[%rcx+112], r10
        movq	[%rcx+120], r11
        sbbq	rax, 0
        addq	rsp, 128
        repz retq
sp_2048_cond_sub_16 ENDP
; /* Reduce the number back to 2048 bits using Montgomery reduction.
;  *
;  * a   A single precision number to reduce in place.
;  * m   The single precision number representing the modulus.
;  * mp  The digit representing the negative inverse of m mod 2^n.
;  */
sp_2048_mont_reduce_16 PROC
        movq	rcx, rdx
        movq	r9, rcx
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        xorq	rsi, rsi
        ; i = 0
        movq	r10, 16
        movq	r15, [%r9]
        movq	rdi, [%r9+8]
L_mont_loop_16:
        ; mu = a[i] * mp
        movq	r13, r15
        imulq	r13, r8
        ; a[i+0] += m[0] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx]
        addq	r15, rax
        adcq	r12, rdx
        ; a[i+1] += m[1] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+8]
        movq	r15, rdi
        addq	r15, rax
        adcq	r11, rdx
        addq	r15, r12
        adcq	r11, 0
        ; a[i+2] += m[2] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+16]
        movq	rdi, [%r9+16]
        addq	rdi, rax
        adcq	r12, rdx
        addq	rdi, r11
        adcq	r12, 0
        ; a[i+3] += m[3] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+24]
        movq	r14, [%r9+24]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+24], r14
        adcq	r11, 0
        ; a[i+4] += m[4] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+32]
        movq	r14, [%r9+32]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+32], r14
        adcq	r12, 0
        ; a[i+5] += m[5] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+40]
        movq	r14, [%r9+40]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+40], r14
        adcq	r11, 0
        ; a[i+6] += m[6] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+48]
        movq	r14, [%r9+48]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+48], r14
        adcq	r12, 0
        ; a[i+7] += m[7] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+56]
        movq	r14, [%r9+56]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+56], r14
        adcq	r11, 0
        ; a[i+8] += m[8] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+64]
        movq	r14, [%r9+64]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+64], r14
        adcq	r12, 0
        ; a[i+9] += m[9] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+72]
        movq	r14, [%r9+72]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+72], r14
        adcq	r11, 0
        ; a[i+10] += m[10] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+80]
        movq	r14, [%r9+80]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+80], r14
        adcq	r12, 0
        ; a[i+11] += m[11] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+88]
        movq	r14, [%r9+88]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+88], r14
        adcq	r11, 0
        ; a[i+12] += m[12] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+96]
        movq	r14, [%r9+96]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+96], r14
        adcq	r12, 0
        ; a[i+13] += m[13] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+104]
        movq	r14, [%r9+104]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+104], r14
        adcq	r11, 0
        ; a[i+14] += m[14] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+112]
        movq	r14, [%r9+112]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+112], r14
        adcq	r12, 0
        ; a[i+15] += m[15] * mu
        movq	rax, r13
        mulq	[%rcx+120]
        movq	r14, [%r9+120]
        addq	r12, rax
        adcq	rdx, rsi
        movq	rsi, 0
        adcq	rsi, 0
        addq	r14, r12
        movq	[%r9+120], r14
        adcq	[%r9+128], rdx
        adcq	rsi, 0
        ; i += 1
        addq	r9, 8
        decq	r10
        jnz	L_mont_loop_16
        movq	[%r9], r15
        movq	[%r9+8], rdi
        negq	rsi
        movq	r9, rsi
        movq	r8, rcx
        movq	rdx, r9
        movq	rcx, r9
        subq	rcx, 128
        callq	sp_2048_cond_sub_16
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        repz retq
sp_2048_mont_reduce_16 ENDP
; /* Mul a by digit b into r. (r = a * b)
;  *
;  * r  A single precision integer.
;  * a  A single precision integer.
;  * b  A single precision digit.
;  */
sp_2048_mul_d_16 PROC
        movq	rcx, rdx
        movq	r9, rcx
        push	r12
        ; A[0] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx]
        movq	r10, rax
        movq	r11, rdx
        movq	[%r9], r10
        ; A[1] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+8]
        addq	r11, rax
        movq	[%r9+8], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[2] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+16]
        addq	r12, rax
        movq	[%r9+16], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; A[3] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx+24]
        addq	r10, rax
        movq	[%r9+24], r10
        adcq	r11, rdx
        adcq	r12, 0
        ; A[4] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+32]
        addq	r11, rax
        movq	[%r9+32], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[5] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+40]
        addq	r12, rax
        movq	[%r9+40], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; A[6] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx+48]
        addq	r10, rax
        movq	[%r9+48], r10
        adcq	r11, rdx
        adcq	r12, 0
        ; A[7] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+56]
        addq	r11, rax
        movq	[%r9+56], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[8] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+64]
        addq	r12, rax
        movq	[%r9+64], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; A[9] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx+72]
        addq	r10, rax
        movq	[%r9+72], r10
        adcq	r11, rdx
        adcq	r12, 0
        ; A[10] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+80]
        addq	r11, rax
        movq	[%r9+80], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[11] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+88]
        addq	r12, rax
        movq	[%r9+88], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; A[12] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx+96]
        addq	r10, rax
        movq	[%r9+96], r10
        adcq	r11, rdx
        adcq	r12, 0
        ; A[13] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+104]
        addq	r11, rax
        movq	[%r9+104], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[14] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+112]
        addq	r12, rax
        movq	[%r9+112], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; # A[15] * B
        movq	rax, r8
        mulq	[%rcx+120]
        addq	r10, rax
        adcq	r11, rdx
        movq	[%r9+120], r10
        movq	[%r9+128], r11
        pop	r12
        repz retq
sp_2048_mul_d_16 ENDP
IFDEF HAVE_INTEL_AVX2
; /* Mul a by digit b into r. (r = a * b)
;  *
;  * r  A single precision integer.
;  * a  A single precision integer.
;  * b  A single precision digit.
;  */
sp_2048_mul_d_avx2_16 PROC
        movq	rax, rdx
        push	r12
        push	r13
        ; A[0] * B
        movq	rdx, r8
        xorq	r13, r13
        mulxq	r12, r11, [%rax]
        movq	[%rcx], r11
        ; A[1] * B
        mulxq	r10, r9, [%rax+8]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+8], r12
        adoxq	r11, r10
        ; A[2] * B
        mulxq	r10, r9, [%rax+16]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+16], r11
        adoxq	r12, r10
        ; A[3] * B
        mulxq	r10, r9, [%rax+24]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+24], r12
        adoxq	r11, r10
        ; A[4] * B
        mulxq	r10, r9, [%rax+32]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+32], r11
        adoxq	r12, r10
        ; A[5] * B
        mulxq	r10, r9, [%rax+40]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+40], r12
        adoxq	r11, r10
        ; A[6] * B
        mulxq	r10, r9, [%rax+48]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+48], r11
        adoxq	r12, r10
        ; A[7] * B
        mulxq	r10, r9, [%rax+56]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+56], r12
        adoxq	r11, r10
        ; A[8] * B
        mulxq	r10, r9, [%rax+64]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+64], r11
        adoxq	r12, r10
        ; A[9] * B
        mulxq	r10, r9, [%rax+72]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+72], r12
        adoxq	r11, r10
        ; A[10] * B
        mulxq	r10, r9, [%rax+80]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+80], r11
        adoxq	r12, r10
        ; A[11] * B
        mulxq	r10, r9, [%rax+88]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+88], r12
        adoxq	r11, r10
        ; A[12] * B
        mulxq	r10, r9, [%rax+96]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+96], r11
        adoxq	r12, r10
        ; A[13] * B
        mulxq	r10, r9, [%rax+104]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+104], r12
        adoxq	r11, r10
        ; A[14] * B
        mulxq	r10, r9, [%rax+112]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+112], r11
        adoxq	r12, r10
        ; A[15] * B
        mulxq	r10, r9, [%rax+120]
        movq	r11, r13
        adcxq	r12, r9
        adoxq	r11, r10
        adcxq	r11, r13
        movq	[%rcx+120], r12
        movq	[%rcx+128], r11
        pop	r13
        pop	r12
        repz retq
sp_2048_mul_d_avx2_16 ENDP
ENDIF
; /* Compare a with b in constant time.
;  *
;  * a  A single precision integer.
;  * b  A single precision integer.
;  * return -ve, 0 or +ve if a is less than, equal to or greater than b
;  * respectively.
;  */
sp_2048_cmp_16 PROC
        push	r12
        xorq	r9, r9
        movq	r8, -1
        movq	rax, -1
        movq	r10, 1
        movq	r11, [%rcx+120]
        movq	r12, [%rdx+120]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+112]
        movq	r12, [%rdx+112]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+104]
        movq	r12, [%rdx+104]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+96]
        movq	r12, [%rdx+96]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+88]
        movq	r12, [%rdx+88]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+80]
        movq	r12, [%rdx+80]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+72]
        movq	r12, [%rdx+72]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+64]
        movq	r12, [%rdx+64]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+56]
        movq	r12, [%rdx+56]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+48]
        movq	r12, [%rdx+48]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+40]
        movq	r12, [%rdx+40]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+32]
        movq	r12, [%rdx+32]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+24]
        movq	r12, [%rdx+24]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+16]
        movq	r12, [%rdx+16]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+8]
        movq	r12, [%rdx+8]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx]
        movq	r12, [%rdx]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        xorq	rax, r8
        pop	r12
        repz retq
sp_2048_cmp_16 ENDP
IFDEF HAVE_INTEL_AVX2
; /* Reduce the number back to 2048 bits using Montgomery reduction.
;  *
;  * a   A single precision number to reduce in place.
;  * m   The single precision number representing the modulus.
;  * mp  The digit representing the negative inverse of m mod 2^n.
;  */
sp_2048_mont_reduce_avx2_16 PROC
        movq	rax, rdx
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        xorq	rdi, rdi
        ; i = 0
        movq	r11, 16
        movq	r15, [%rcx]
        xorq	r14, r14
L_mont_loop_avx2_16:
        ; mu = a[i] * mp
        movq	rdx, r15
        mulxq	r10, rdx, r8
        movq	r12, r15
        ; a[i+0] += m[0] * mu
        mulxq	r10, r9, [%rax]
        movq	r15, [%rcx+8]
        adcxq	r12, r9
        adoxq	r15, r10
        ; a[i+1] += m[1] * mu
        mulxq	r10, r9, [%rax+8]
        movq	r12, [%rcx+16]
        adcxq	r15, r9
        adoxq	r12, r10
        ; a[i+2] += m[2] * mu
        mulxq	r10, r9, [%rax+16]
        movq	r13, [%rcx+24]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+16], r12
        ; a[i+3] += m[3] * mu
        mulxq	r10, r9, [%rax+24]
        movq	r12, [%rcx+32]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+24], r13
        ; a[i+4] += m[4] * mu
        mulxq	r10, r9, [%rax+32]
        movq	r13, [%rcx+40]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+32], r12
        ; a[i+5] += m[5] * mu
        mulxq	r10, r9, [%rax+40]
        movq	r12, [%rcx+48]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+40], r13
        ; a[i+6] += m[6] * mu
        mulxq	r10, r9, [%rax+48]
        movq	r13, [%rcx+56]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+48], r12
        ; a[i+7] += m[7] * mu
        mulxq	r10, r9, [%rax+56]
        movq	r12, [%rcx+64]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+56], r13
        ; a[i+8] += m[8] * mu
        mulxq	r10, r9, [%rax+64]
        movq	r13, [%rcx+72]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+64], r12
        ; a[i+9] += m[9] * mu
        mulxq	r10, r9, [%rax+72]
        movq	r12, [%rcx+80]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+72], r13
        ; a[i+10] += m[10] * mu
        mulxq	r10, r9, [%rax+80]
        movq	r13, [%rcx+88]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+80], r12
        ; a[i+11] += m[11] * mu
        mulxq	r10, r9, [%rax+88]
        movq	r12, [%rcx+96]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+88], r13
        ; a[i+12] += m[12] * mu
        mulxq	r10, r9, [%rax+96]
        movq	r13, [%rcx+104]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+96], r12
        ; a[i+13] += m[13] * mu
        mulxq	r10, r9, [%rax+104]
        movq	r12, [%rcx+112]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+104], r13
        ; a[i+14] += m[14] * mu
        mulxq	r10, r9, [%rax+112]
        movq	r13, [%rcx+120]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+112], r12
        ; a[i+15] += m[15] * mu
        mulxq	r10, r9, [%rax+120]
        movq	r12, [%rcx+128]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+120], r13
        adcxq	r12, rdi
        movq	rdi, r14
        adoxq	rdi, r14
        adcxq	rdi, r14
        movq	[%rcx+128], r12
        ; i += 1
        addq	rcx, 8
        decq	r11
        jnz	L_mont_loop_avx2_16
        movq	[%rcx], r15
        negq	rdi
        movq	r9, rdi
        movq	r8, rax
        movq	rdx, rcx
        movq	rcx, rcx
        subq	rcx, 128
        callq	sp_2048_cond_sub_16
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        repz retq
sp_2048_mont_reduce_avx2_16 ENDP
ENDIF
; /* Conditionally subtract b from a using the mask m.
;  * m is -1 to subtract and 0 when not copying.
;  *
;  * r  A single precision number representing condition subtract result.
;  * a  A single precision number to subtract from.
;  * b  A single precision number to subtract.
;  * m  Mask value to apply.
;  */
sp_2048_cond_sub_32 PROC
        subq	rsp, 256
        movq	rax, 0
        movq	r10, [%r8]
        movq	r11, [%r8+8]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp], r10
        movq	[%rsp+8], r11
        movq	r10, [%r8+16]
        movq	r11, [%r8+24]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+16], r10
        movq	[%rsp+24], r11
        movq	r10, [%r8+32]
        movq	r11, [%r8+40]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+32], r10
        movq	[%rsp+40], r11
        movq	r10, [%r8+48]
        movq	r11, [%r8+56]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+48], r10
        movq	[%rsp+56], r11
        movq	r10, [%r8+64]
        movq	r11, [%r8+72]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+64], r10
        movq	[%rsp+72], r11
        movq	r10, [%r8+80]
        movq	r11, [%r8+88]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+80], r10
        movq	[%rsp+88], r11
        movq	r10, [%r8+96]
        movq	r11, [%r8+104]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+96], r10
        movq	[%rsp+104], r11
        movq	r10, [%r8+112]
        movq	r11, [%r8+120]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+112], r10
        movq	[%rsp+120], r11
        movq	r10, [%r8+128]
        movq	r11, [%r8+136]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+128], r10
        movq	[%rsp+136], r11
        movq	r10, [%r8+144]
        movq	r11, [%r8+152]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+144], r10
        movq	[%rsp+152], r11
        movq	r10, [%r8+160]
        movq	r11, [%r8+168]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+160], r10
        movq	[%rsp+168], r11
        movq	r10, [%r8+176]
        movq	r11, [%r8+184]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+176], r10
        movq	[%rsp+184], r11
        movq	r10, [%r8+192]
        movq	r11, [%r8+200]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+192], r10
        movq	[%rsp+200], r11
        movq	r10, [%r8+208]
        movq	r11, [%r8+216]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+208], r10
        movq	[%rsp+216], r11
        movq	r10, [%r8+224]
        movq	r11, [%r8+232]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+224], r10
        movq	[%rsp+232], r11
        movq	r10, [%r8+240]
        movq	r11, [%r8+248]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+240], r10
        movq	[%rsp+248], r11
        movq	r10, [%rdx]
        movq	r8, [%rsp]
        subq	r10, r8
        movq	r11, [%rdx+8]
        movq	r8, [%rsp+8]
        sbbq	r11, r8
        movq	[%rcx], r10
        movq	r10, [%rdx+16]
        movq	r8, [%rsp+16]
        sbbq	r10, r8
        movq	[%rcx+8], r11
        movq	r11, [%rdx+24]
        movq	r8, [%rsp+24]
        sbbq	r11, r8
        movq	[%rcx+16], r10
        movq	r10, [%rdx+32]
        movq	r8, [%rsp+32]
        sbbq	r10, r8
        movq	[%rcx+24], r11
        movq	r11, [%rdx+40]
        movq	r8, [%rsp+40]
        sbbq	r11, r8
        movq	[%rcx+32], r10
        movq	r10, [%rdx+48]
        movq	r8, [%rsp+48]
        sbbq	r10, r8
        movq	[%rcx+40], r11
        movq	r11, [%rdx+56]
        movq	r8, [%rsp+56]
        sbbq	r11, r8
        movq	[%rcx+48], r10
        movq	r10, [%rdx+64]
        movq	r8, [%rsp+64]
        sbbq	r10, r8
        movq	[%rcx+56], r11
        movq	r11, [%rdx+72]
        movq	r8, [%rsp+72]
        sbbq	r11, r8
        movq	[%rcx+64], r10
        movq	r10, [%rdx+80]
        movq	r8, [%rsp+80]
        sbbq	r10, r8
        movq	[%rcx+72], r11
        movq	r11, [%rdx+88]
        movq	r8, [%rsp+88]
        sbbq	r11, r8
        movq	[%rcx+80], r10
        movq	r10, [%rdx+96]
        movq	r8, [%rsp+96]
        sbbq	r10, r8
        movq	[%rcx+88], r11
        movq	r11, [%rdx+104]
        movq	r8, [%rsp+104]
        sbbq	r11, r8
        movq	[%rcx+96], r10
        movq	r10, [%rdx+112]
        movq	r8, [%rsp+112]
        sbbq	r10, r8
        movq	[%rcx+104], r11
        movq	r11, [%rdx+120]
        movq	r8, [%rsp+120]
        sbbq	r11, r8
        movq	[%rcx+112], r10
        movq	r10, [%rdx+128]
        movq	r8, [%rsp+128]
        sbbq	r10, r8
        movq	[%rcx+120], r11
        movq	r11, [%rdx+136]
        movq	r8, [%rsp+136]
        sbbq	r11, r8
        movq	[%rcx+128], r10
        movq	r10, [%rdx+144]
        movq	r8, [%rsp+144]
        sbbq	r10, r8
        movq	[%rcx+136], r11
        movq	r11, [%rdx+152]
        movq	r8, [%rsp+152]
        sbbq	r11, r8
        movq	[%rcx+144], r10
        movq	r10, [%rdx+160]
        movq	r8, [%rsp+160]
        sbbq	r10, r8
        movq	[%rcx+152], r11
        movq	r11, [%rdx+168]
        movq	r8, [%rsp+168]
        sbbq	r11, r8
        movq	[%rcx+160], r10
        movq	r10, [%rdx+176]
        movq	r8, [%rsp+176]
        sbbq	r10, r8
        movq	[%rcx+168], r11
        movq	r11, [%rdx+184]
        movq	r8, [%rsp+184]
        sbbq	r11, r8
        movq	[%rcx+176], r10
        movq	r10, [%rdx+192]
        movq	r8, [%rsp+192]
        sbbq	r10, r8
        movq	[%rcx+184], r11
        movq	r11, [%rdx+200]
        movq	r8, [%rsp+200]
        sbbq	r11, r8
        movq	[%rcx+192], r10
        movq	r10, [%rdx+208]
        movq	r8, [%rsp+208]
        sbbq	r10, r8
        movq	[%rcx+200], r11
        movq	r11, [%rdx+216]
        movq	r8, [%rsp+216]
        sbbq	r11, r8
        movq	[%rcx+208], r10
        movq	r10, [%rdx+224]
        movq	r8, [%rsp+224]
        sbbq	r10, r8
        movq	[%rcx+216], r11
        movq	r11, [%rdx+232]
        movq	r8, [%rsp+232]
        sbbq	r11, r8
        movq	[%rcx+224], r10
        movq	r10, [%rdx+240]
        movq	r8, [%rsp+240]
        sbbq	r10, r8
        movq	[%rcx+232], r11
        movq	r11, [%rdx+248]
        movq	r8, [%rsp+248]
        sbbq	r11, r8
        movq	[%rcx+240], r10
        movq	[%rcx+248], r11
        sbbq	rax, 0
        addq	rsp, 256
        repz retq
sp_2048_cond_sub_32 ENDP
; /* Reduce the number back to 2048 bits using Montgomery reduction.
;  *
;  * a   A single precision number to reduce in place.
;  * m   The single precision number representing the modulus.
;  * mp  The digit representing the negative inverse of m mod 2^n.
;  */
sp_2048_mont_reduce_32 PROC
        movq	rcx, rdx
        movq	r9, rcx
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        xorq	rsi, rsi
        ; i = 0
        movq	r10, 32
        movq	r15, [%r9]
        movq	rdi, [%r9+8]
L_mont_loop_32:
        ; mu = a[i] * mp
        movq	r13, r15
        imulq	r13, r8
        ; a[i+0] += m[0] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx]
        addq	r15, rax
        adcq	r12, rdx
        ; a[i+1] += m[1] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+8]
        movq	r15, rdi
        addq	r15, rax
        adcq	r11, rdx
        addq	r15, r12
        adcq	r11, 0
        ; a[i+2] += m[2] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+16]
        movq	rdi, [%r9+16]
        addq	rdi, rax
        adcq	r12, rdx
        addq	rdi, r11
        adcq	r12, 0
        ; a[i+3] += m[3] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+24]
        movq	r14, [%r9+24]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+24], r14
        adcq	r11, 0
        ; a[i+4] += m[4] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+32]
        movq	r14, [%r9+32]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+32], r14
        adcq	r12, 0
        ; a[i+5] += m[5] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+40]
        movq	r14, [%r9+40]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+40], r14
        adcq	r11, 0
        ; a[i+6] += m[6] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+48]
        movq	r14, [%r9+48]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+48], r14
        adcq	r12, 0
        ; a[i+7] += m[7] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+56]
        movq	r14, [%r9+56]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+56], r14
        adcq	r11, 0
        ; a[i+8] += m[8] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+64]
        movq	r14, [%r9+64]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+64], r14
        adcq	r12, 0
        ; a[i+9] += m[9] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+72]
        movq	r14, [%r9+72]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+72], r14
        adcq	r11, 0
        ; a[i+10] += m[10] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+80]
        movq	r14, [%r9+80]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+80], r14
        adcq	r12, 0
        ; a[i+11] += m[11] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+88]
        movq	r14, [%r9+88]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+88], r14
        adcq	r11, 0
        ; a[i+12] += m[12] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+96]
        movq	r14, [%r9+96]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+96], r14
        adcq	r12, 0
        ; a[i+13] += m[13] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+104]
        movq	r14, [%r9+104]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+104], r14
        adcq	r11, 0
        ; a[i+14] += m[14] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+112]
        movq	r14, [%r9+112]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+112], r14
        adcq	r12, 0
        ; a[i+15] += m[15] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+120]
        movq	r14, [%r9+120]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+120], r14
        adcq	r11, 0
        ; a[i+16] += m[16] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+128]
        movq	r14, [%r9+128]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+128], r14
        adcq	r12, 0
        ; a[i+17] += m[17] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+136]
        movq	r14, [%r9+136]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+136], r14
        adcq	r11, 0
        ; a[i+18] += m[18] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+144]
        movq	r14, [%r9+144]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+144], r14
        adcq	r12, 0
        ; a[i+19] += m[19] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+152]
        movq	r14, [%r9+152]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+152], r14
        adcq	r11, 0
        ; a[i+20] += m[20] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+160]
        movq	r14, [%r9+160]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+160], r14
        adcq	r12, 0
        ; a[i+21] += m[21] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+168]
        movq	r14, [%r9+168]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+168], r14
        adcq	r11, 0
        ; a[i+22] += m[22] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+176]
        movq	r14, [%r9+176]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+176], r14
        adcq	r12, 0
        ; a[i+23] += m[23] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+184]
        movq	r14, [%r9+184]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+184], r14
        adcq	r11, 0
        ; a[i+24] += m[24] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+192]
        movq	r14, [%r9+192]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+192], r14
        adcq	r12, 0
        ; a[i+25] += m[25] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+200]
        movq	r14, [%r9+200]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+200], r14
        adcq	r11, 0
        ; a[i+26] += m[26] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+208]
        movq	r14, [%r9+208]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+208], r14
        adcq	r12, 0
        ; a[i+27] += m[27] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+216]
        movq	r14, [%r9+216]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+216], r14
        adcq	r11, 0
        ; a[i+28] += m[28] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+224]
        movq	r14, [%r9+224]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+224], r14
        adcq	r12, 0
        ; a[i+29] += m[29] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+232]
        movq	r14, [%r9+232]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+232], r14
        adcq	r11, 0
        ; a[i+30] += m[30] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+240]
        movq	r14, [%r9+240]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+240], r14
        adcq	r12, 0
        ; a[i+31] += m[31] * mu
        movq	rax, r13
        mulq	[%rcx+248]
        movq	r14, [%r9+248]
        addq	r12, rax
        adcq	rdx, rsi
        movq	rsi, 0
        adcq	rsi, 0
        addq	r14, r12
        movq	[%r9+248], r14
        adcq	[%r9+256], rdx
        adcq	rsi, 0
        ; i += 1
        addq	r9, 8
        decq	r10
        jnz	L_mont_loop_32
        movq	[%r9], r15
        movq	[%r9+8], rdi
        negq	rsi
        movq	r9, rsi
        movq	r8, rcx
        movq	rdx, r9
        movq	rcx, r9
        subq	rcx, 256
        callq	sp_2048_cond_sub_32
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        repz retq
sp_2048_mont_reduce_32 ENDP
IFDEF HAVE_INTEL_AVX2
; /* Mul a by digit b into r. (r = a * b)
;  *
;  * r  A single precision integer.
;  * a  A single precision integer.
;  * b  A single precision digit.
;  */
sp_2048_mul_d_avx2_32 PROC
        movq	rax, rdx
        push	r12
        push	r13
        ; A[0] * B
        movq	rdx, r8
        xorq	r13, r13
        mulxq	r12, r11, [%rax]
        movq	[%rcx], r11
        ; A[1] * B
        mulxq	r10, r9, [%rax+8]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+8], r12
        adoxq	r11, r10
        ; A[2] * B
        mulxq	r10, r9, [%rax+16]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+16], r11
        adoxq	r12, r10
        ; A[3] * B
        mulxq	r10, r9, [%rax+24]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+24], r12
        adoxq	r11, r10
        ; A[4] * B
        mulxq	r10, r9, [%rax+32]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+32], r11
        adoxq	r12, r10
        ; A[5] * B
        mulxq	r10, r9, [%rax+40]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+40], r12
        adoxq	r11, r10
        ; A[6] * B
        mulxq	r10, r9, [%rax+48]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+48], r11
        adoxq	r12, r10
        ; A[7] * B
        mulxq	r10, r9, [%rax+56]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+56], r12
        adoxq	r11, r10
        ; A[8] * B
        mulxq	r10, r9, [%rax+64]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+64], r11
        adoxq	r12, r10
        ; A[9] * B
        mulxq	r10, r9, [%rax+72]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+72], r12
        adoxq	r11, r10
        ; A[10] * B
        mulxq	r10, r9, [%rax+80]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+80], r11
        adoxq	r12, r10
        ; A[11] * B
        mulxq	r10, r9, [%rax+88]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+88], r12
        adoxq	r11, r10
        ; A[12] * B
        mulxq	r10, r9, [%rax+96]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+96], r11
        adoxq	r12, r10
        ; A[13] * B
        mulxq	r10, r9, [%rax+104]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+104], r12
        adoxq	r11, r10
        ; A[14] * B
        mulxq	r10, r9, [%rax+112]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+112], r11
        adoxq	r12, r10
        ; A[15] * B
        mulxq	r10, r9, [%rax+120]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+120], r12
        adoxq	r11, r10
        ; A[16] * B
        mulxq	r10, r9, [%rax+128]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+128], r11
        adoxq	r12, r10
        ; A[17] * B
        mulxq	r10, r9, [%rax+136]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+136], r12
        adoxq	r11, r10
        ; A[18] * B
        mulxq	r10, r9, [%rax+144]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+144], r11
        adoxq	r12, r10
        ; A[19] * B
        mulxq	r10, r9, [%rax+152]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+152], r12
        adoxq	r11, r10
        ; A[20] * B
        mulxq	r10, r9, [%rax+160]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+160], r11
        adoxq	r12, r10
        ; A[21] * B
        mulxq	r10, r9, [%rax+168]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+168], r12
        adoxq	r11, r10
        ; A[22] * B
        mulxq	r10, r9, [%rax+176]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+176], r11
        adoxq	r12, r10
        ; A[23] * B
        mulxq	r10, r9, [%rax+184]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+184], r12
        adoxq	r11, r10
        ; A[24] * B
        mulxq	r10, r9, [%rax+192]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+192], r11
        adoxq	r12, r10
        ; A[25] * B
        mulxq	r10, r9, [%rax+200]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+200], r12
        adoxq	r11, r10
        ; A[26] * B
        mulxq	r10, r9, [%rax+208]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+208], r11
        adoxq	r12, r10
        ; A[27] * B
        mulxq	r10, r9, [%rax+216]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+216], r12
        adoxq	r11, r10
        ; A[28] * B
        mulxq	r10, r9, [%rax+224]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+224], r11
        adoxq	r12, r10
        ; A[29] * B
        mulxq	r10, r9, [%rax+232]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+232], r12
        adoxq	r11, r10
        ; A[30] * B
        mulxq	r10, r9, [%rax+240]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+240], r11
        adoxq	r12, r10
        ; A[31] * B
        mulxq	r10, r9, [%rax+248]
        movq	r11, r13
        adcxq	r12, r9
        adoxq	r11, r10
        adcxq	r11, r13
        movq	[%rcx+248], r12
        movq	[%rcx+256], r11
        pop	r13
        pop	r12
        repz retq
sp_2048_mul_d_avx2_32 ENDP
ENDIF
; /* Compare a with b in constant time.
;  *
;  * a  A single precision integer.
;  * b  A single precision integer.
;  * return -ve, 0 or +ve if a is less than, equal to or greater than b
;  * respectively.
;  */
sp_2048_cmp_32 PROC
        push	r12
        xorq	r9, r9
        movq	r8, -1
        movq	rax, -1
        movq	r10, 1
        movq	r11, [%rcx+248]
        movq	r12, [%rdx+248]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+240]
        movq	r12, [%rdx+240]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+232]
        movq	r12, [%rdx+232]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+224]
        movq	r12, [%rdx+224]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+216]
        movq	r12, [%rdx+216]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+208]
        movq	r12, [%rdx+208]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+200]
        movq	r12, [%rdx+200]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+192]
        movq	r12, [%rdx+192]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+184]
        movq	r12, [%rdx+184]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+176]
        movq	r12, [%rdx+176]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+168]
        movq	r12, [%rdx+168]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+160]
        movq	r12, [%rdx+160]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+152]
        movq	r12, [%rdx+152]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+144]
        movq	r12, [%rdx+144]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+136]
        movq	r12, [%rdx+136]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+128]
        movq	r12, [%rdx+128]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+120]
        movq	r12, [%rdx+120]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+112]
        movq	r12, [%rdx+112]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+104]
        movq	r12, [%rdx+104]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+96]
        movq	r12, [%rdx+96]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+88]
        movq	r12, [%rdx+88]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+80]
        movq	r12, [%rdx+80]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+72]
        movq	r12, [%rdx+72]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+64]
        movq	r12, [%rdx+64]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+56]
        movq	r12, [%rdx+56]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+48]
        movq	r12, [%rdx+48]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+40]
        movq	r12, [%rdx+40]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+32]
        movq	r12, [%rdx+32]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+24]
        movq	r12, [%rdx+24]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+16]
        movq	r12, [%rdx+16]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+8]
        movq	r12, [%rdx+8]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx]
        movq	r12, [%rdx]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        xorq	rax, r8
        pop	r12
        repz retq
sp_2048_cmp_32 ENDP
IFDEF HAVE_INTEL_AVX2
; /* Reduce the number back to 2048 bits using Montgomery reduction.
;  *
;  * a   A single precision number to reduce in place.
;  * m   The single precision number representing the modulus.
;  * mp  The digit representing the negative inverse of m mod 2^n.
;  */
sp_2048_mont_reduce_avx2_32 PROC
        movq	rax, rdx
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        xorq	rdi, rdi
        ; i = 0
        movq	r11, 32
        movq	r15, [%rcx]
        xorq	r14, r14
L_mont_loop_avx2_32:
        ; mu = a[i] * mp
        movq	rdx, r15
        mulxq	r10, rdx, r8
        movq	r12, r15
        ; a[i+0] += m[0] * mu
        mulxq	r10, r9, [%rax]
        movq	r15, [%rcx+8]
        adcxq	r12, r9
        adoxq	r15, r10
        ; a[i+1] += m[1] * mu
        mulxq	r10, r9, [%rax+8]
        movq	r12, [%rcx+16]
        adcxq	r15, r9
        adoxq	r12, r10
        ; a[i+2] += m[2] * mu
        mulxq	r10, r9, [%rax+16]
        movq	r13, [%rcx+24]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+16], r12
        ; a[i+3] += m[3] * mu
        mulxq	r10, r9, [%rax+24]
        movq	r12, [%rcx+32]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+24], r13
        ; a[i+4] += m[4] * mu
        mulxq	r10, r9, [%rax+32]
        movq	r13, [%rcx+40]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+32], r12
        ; a[i+5] += m[5] * mu
        mulxq	r10, r9, [%rax+40]
        movq	r12, [%rcx+48]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+40], r13
        ; a[i+6] += m[6] * mu
        mulxq	r10, r9, [%rax+48]
        movq	r13, [%rcx+56]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+48], r12
        ; a[i+7] += m[7] * mu
        mulxq	r10, r9, [%rax+56]
        movq	r12, [%rcx+64]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+56], r13
        ; a[i+8] += m[8] * mu
        mulxq	r10, r9, [%rax+64]
        movq	r13, [%rcx+72]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+64], r12
        ; a[i+9] += m[9] * mu
        mulxq	r10, r9, [%rax+72]
        movq	r12, [%rcx+80]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+72], r13
        ; a[i+10] += m[10] * mu
        mulxq	r10, r9, [%rax+80]
        movq	r13, [%rcx+88]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+80], r12
        ; a[i+11] += m[11] * mu
        mulxq	r10, r9, [%rax+88]
        movq	r12, [%rcx+96]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+88], r13
        ; a[i+12] += m[12] * mu
        mulxq	r10, r9, [%rax+96]
        movq	r13, [%rcx+104]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+96], r12
        ; a[i+13] += m[13] * mu
        mulxq	r10, r9, [%rax+104]
        movq	r12, [%rcx+112]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+104], r13
        ; a[i+14] += m[14] * mu
        mulxq	r10, r9, [%rax+112]
        movq	r13, [%rcx+120]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+112], r12
        ; a[i+15] += m[15] * mu
        mulxq	r10, r9, [%rax+120]
        movq	r12, [%rcx+128]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+120], r13
        ; a[i+16] += m[16] * mu
        mulxq	r10, r9, [%rax+128]
        movq	r13, [%rcx+136]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+128], r12
        ; a[i+17] += m[17] * mu
        mulxq	r10, r9, [%rax+136]
        movq	r12, [%rcx+144]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+136], r13
        ; a[i+18] += m[18] * mu
        mulxq	r10, r9, [%rax+144]
        movq	r13, [%rcx+152]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+144], r12
        ; a[i+19] += m[19] * mu
        mulxq	r10, r9, [%rax+152]
        movq	r12, [%rcx+160]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+152], r13
        ; a[i+20] += m[20] * mu
        mulxq	r10, r9, [%rax+160]
        movq	r13, [%rcx+168]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+160], r12
        ; a[i+21] += m[21] * mu
        mulxq	r10, r9, [%rax+168]
        movq	r12, [%rcx+176]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+168], r13
        ; a[i+22] += m[22] * mu
        mulxq	r10, r9, [%rax+176]
        movq	r13, [%rcx+184]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+176], r12
        ; a[i+23] += m[23] * mu
        mulxq	r10, r9, [%rax+184]
        movq	r12, [%rcx+192]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+184], r13
        ; a[i+24] += m[24] * mu
        mulxq	r10, r9, [%rax+192]
        movq	r13, [%rcx+200]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+192], r12
        ; a[i+25] += m[25] * mu
        mulxq	r10, r9, [%rax+200]
        movq	r12, [%rcx+208]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+200], r13
        ; a[i+26] += m[26] * mu
        mulxq	r10, r9, [%rax+208]
        movq	r13, [%rcx+216]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+208], r12
        ; a[i+27] += m[27] * mu
        mulxq	r10, r9, [%rax+216]
        movq	r12, [%rcx+224]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+216], r13
        ; a[i+28] += m[28] * mu
        mulxq	r10, r9, [%rax+224]
        movq	r13, [%rcx+232]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+224], r12
        ; a[i+29] += m[29] * mu
        mulxq	r10, r9, [%rax+232]
        movq	r12, [%rcx+240]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+232], r13
        ; a[i+30] += m[30] * mu
        mulxq	r10, r9, [%rax+240]
        movq	r13, [%rcx+248]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+240], r12
        ; a[i+31] += m[31] * mu
        mulxq	r10, r9, [%rax+248]
        movq	r12, [%rcx+256]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+248], r13
        adcxq	r12, rdi
        movq	rdi, r14
        adoxq	rdi, r14
        adcxq	rdi, r14
        movq	[%rcx+256], r12
        ; i += 1
        addq	rcx, 8
        decq	r11
        jnz	L_mont_loop_avx2_32
        movq	[%rcx], r15
        negq	rdi
        movq	r9, rdi
        movq	r8, rax
        movq	rdx, rcx
        movq	rcx, rcx
        subq	rcx, 256
        callq	sp_2048_cond_sub_32
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        repz retq
sp_2048_mont_reduce_avx2_32 ENDP
ENDIF
; /* Shift number left by n bit. (r = a << n)
;  *
;  * r  Result of left shift by n.
;  * a  Number to shift.
;  * n  Amoutnt o shift.
;  */
sp_2048_lshift_32 PROC
        movq	rcx, r8
        push	r12
        movq	r11, 0
        movq	r12, [%rdx+216]
        movq	rax, [%rdx+224]
        movq	r8, [%rdx+232]
        movq	r9, [%rdx+240]
        movq	r10, [%rdx+248]
        shldq	r11, r10, cl
        shldq	r10, r9, cl
        shldq	r9, r8, cl
        shldq	r8, rax, cl
        shldq	rax, r12, cl
        movq	[%rcx+224], rax
        movq	[%rcx+232], r8
        movq	[%rcx+240], r9
        movq	[%rcx+248], r10
        movq	[%rcx+256], r11
        movq	r10, [%rdx+184]
        movq	rax, [%rdx+192]
        movq	r8, [%rdx+200]
        movq	r9, [%rdx+208]
        shldq	r12, r9, cl
        shldq	r9, r8, cl
        shldq	r8, rax, cl
        shldq	rax, r10, cl
        movq	[%rcx+192], rax
        movq	[%rcx+200], r8
        movq	[%rcx+208], r9
        movq	[%rcx+216], r12
        movq	r12, [%rdx+152]
        movq	rax, [%rdx+160]
        movq	r8, [%rdx+168]
        movq	r9, [%rdx+176]
        shldq	r10, r9, cl
        shldq	r9, r8, cl
        shldq	r8, rax, cl
        shldq	rax, r12, cl
        movq	[%rcx+160], rax
        movq	[%rcx+168], r8
        movq	[%rcx+176], r9
        movq	[%rcx+184], r10
        movq	r10, [%rdx+120]
        movq	rax, [%rdx+128]
        movq	r8, [%rdx+136]
        movq	r9, [%rdx+144]
        shldq	r12, r9, cl
        shldq	r9, r8, cl
        shldq	r8, rax, cl
        shldq	rax, r10, cl
        movq	[%rcx+128], rax
        movq	[%rcx+136], r8
        movq	[%rcx+144], r9
        movq	[%rcx+152], r12
        movq	r12, [%rdx+88]
        movq	rax, [%rdx+96]
        movq	r8, [%rdx+104]
        movq	r9, [%rdx+112]
        shldq	r10, r9, cl
        shldq	r9, r8, cl
        shldq	r8, rax, cl
        shldq	rax, r12, cl
        movq	[%rcx+96], rax
        movq	[%rcx+104], r8
        movq	[%rcx+112], r9
        movq	[%rcx+120], r10
        movq	r10, [%rdx+56]
        movq	rax, [%rdx+64]
        movq	r8, [%rdx+72]
        movq	r9, [%rdx+80]
        shldq	r12, r9, cl
        shldq	r9, r8, cl
        shldq	r8, rax, cl
        shldq	rax, r10, cl
        movq	[%rcx+64], rax
        movq	[%rcx+72], r8
        movq	[%rcx+80], r9
        movq	[%rcx+88], r12
        movq	r12, [%rdx+24]
        movq	rax, [%rdx+32]
        movq	r8, [%rdx+40]
        movq	r9, [%rdx+48]
        shldq	r10, r9, cl
        shldq	r9, r8, cl
        shldq	r8, rax, cl
        shldq	rax, r12, cl
        movq	[%rcx+32], rax
        movq	[%rcx+40], r8
        movq	[%rcx+48], r9
        movq	[%rcx+56], r10
        movq	rax, [%rdx]
        movq	r8, [%rdx+8]
        movq	r9, [%rdx+16]
        shldq	r12, r9, cl
        shldq	r9, r8, cl
        shldq	r8, rax, cl
        shlq	rax, cl
        movq	[%rcx], rax
        movq	[%rcx+8], r8
        movq	[%rcx+16], r9
        movq	[%rcx+24], r12
        pop	r12
        repz retq
; /* Multiply a and b into r. (r = a * b)
;  *
;  * r  A single precision integer.
;  * a  A single precision integer.
;  * b  A single precision integer.
;  */
sp_3072_mul_24 PROC
        movq	rcx, rdx
        movq	r9, rcx
        push	r12
        subq	rsp, 192
        ; A[0] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx]
        xorq	r12, r12
        movq	[%rsp], rax
        movq	r11, rdx
        ; A[0] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx]
        xorq	r10, r10
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[1] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+8]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        movq	[%rsp+8], r11
        ; A[0] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx]
        xorq	r11, r11
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[1] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[2] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        movq	[%rsp+16], r12
        ; A[0] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx]
        xorq	r12, r12
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[1] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+8]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[2] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+16]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[3] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+24]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        movq	[%rsp+24], r10
        ; A[0] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx]
        xorq	r10, r10
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[1] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+8]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[2] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+16]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[3] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+24]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[4] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+32]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        movq	[%rsp+32], r11
        ; A[0] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx]
        xorq	r11, r11
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[1] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[2] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[3] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[4] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[5] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        movq	[%rsp+40], r12
        ; A[0] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx]
        xorq	r12, r12
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[1] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+8]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[2] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+16]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[3] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+24]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[4] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+32]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[5] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+40]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[6] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+48]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        movq	[%rsp+48], r10
        ; A[0] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx]
        xorq	r10, r10
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[1] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+8]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[2] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+16]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[3] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+24]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[4] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+32]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[5] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+40]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[6] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+48]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[7] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+56]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        movq	[%rsp+56], r11
        ; A[0] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx]
        xorq	r11, r11
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[1] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[2] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[3] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[4] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[5] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[6] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+48]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[7] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+56]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[8] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+64]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        movq	[%rsp+64], r12
        ; A[0] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx]
        xorq	r12, r12
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[1] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+8]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[2] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+16]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[3] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+24]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[4] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+32]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[5] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+40]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[6] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+48]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[7] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+56]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[8] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+64]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[9] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+72]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        movq	[%rsp+72], r10
        ; A[0] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx]
        xorq	r10, r10
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[1] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+8]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[2] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+16]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[3] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+24]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[4] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+32]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[5] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+40]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[6] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+48]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[7] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+56]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[8] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+64]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[9] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+72]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[10] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+80]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        movq	[%rsp+80], r11
        ; A[0] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx]
        xorq	r11, r11
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[1] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[2] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[3] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[4] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[5] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[6] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+48]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[7] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+56]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[8] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+64]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[9] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+72]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[10] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+80]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[11] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+88]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        movq	[%rsp+88], r12
        ; A[0] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx]
        xorq	r12, r12
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[1] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+8]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[2] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+16]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[3] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+24]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[4] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+32]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[5] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+40]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[6] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+48]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[7] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+56]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[8] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+64]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[9] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+72]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[10] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+80]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[11] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+88]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[12] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+96]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        movq	[%rsp+96], r10
        ; A[0] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx]
        xorq	r10, r10
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[1] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+8]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[2] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+16]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[3] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+24]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[4] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+32]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[5] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+40]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[6] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+48]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[7] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+56]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[8] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+64]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[9] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+72]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[10] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+80]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[11] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+88]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[12] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+96]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[13] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+104]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        movq	[%rsp+104], r11
        ; A[0] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx]
        xorq	r11, r11
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[1] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[2] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[3] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[4] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[5] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[6] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+48]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[7] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+56]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[8] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+64]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[9] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+72]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[10] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+80]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[11] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+88]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[12] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+96]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[13] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+104]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[14] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+112]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        movq	[%rsp+112], r12
        ; A[0] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx]
        xorq	r12, r12
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[1] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+8]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[2] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+16]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[3] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+24]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[4] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+32]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[5] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+40]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[6] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+48]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[7] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+56]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[8] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+64]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[9] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+72]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[10] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+80]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[11] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+88]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[12] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+96]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[13] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+104]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[14] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+112]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[15] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+120]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        movq	[%rsp+120], r10
        ; A[0] * B[16]
        movq	rax, [%r8+128]
        mulq	[%rcx]
        xorq	r10, r10
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[1] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+8]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[2] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+16]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[3] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+24]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[4] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+32]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[5] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+40]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[6] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+48]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[7] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+56]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[8] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+64]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[9] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+72]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[10] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+80]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[11] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+88]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[12] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+96]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[13] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+104]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[14] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+112]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[15] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+120]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[16] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+128]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        movq	[%rsp+128], r11
        ; A[0] * B[17]
        movq	rax, [%r8+136]
        mulq	[%rcx]
        xorq	r11, r11
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[1] * B[16]
        movq	rax, [%r8+128]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[2] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[3] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[4] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[5] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[6] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+48]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[7] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+56]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[8] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+64]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[9] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+72]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[10] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+80]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[11] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+88]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[12] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+96]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[13] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+104]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[14] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+112]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[15] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+120]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[16] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+128]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[17] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+136]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        movq	[%rsp+136], r12
        ; A[0] * B[18]
        movq	rax, [%r8+144]
        mulq	[%rcx]
        xorq	r12, r12
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[1] * B[17]
        movq	rax, [%r8+136]
        mulq	[%rcx+8]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[2] * B[16]
        movq	rax, [%r8+128]
        mulq	[%rcx+16]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[3] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+24]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[4] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+32]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[5] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+40]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[6] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+48]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[7] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+56]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[8] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+64]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[9] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+72]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[10] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+80]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[11] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+88]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[12] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+96]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[13] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+104]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[14] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+112]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[15] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+120]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[16] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+128]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[17] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+136]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[18] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+144]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        movq	[%rsp+144], r10
        ; A[0] * B[19]
        movq	rax, [%r8+152]
        mulq	[%rcx]
        xorq	r10, r10
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[1] * B[18]
        movq	rax, [%r8+144]
        mulq	[%rcx+8]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[2] * B[17]
        movq	rax, [%r8+136]
        mulq	[%rcx+16]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[3] * B[16]
        movq	rax, [%r8+128]
        mulq	[%rcx+24]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[4] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+32]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[5] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+40]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[6] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+48]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[7] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+56]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[8] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+64]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[9] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+72]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[10] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+80]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[11] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+88]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[12] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+96]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[13] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+104]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[14] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+112]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[15] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+120]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[16] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+128]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[17] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+136]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[18] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+144]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[19] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+152]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        movq	[%rsp+152], r11
        ; A[0] * B[20]
        movq	rax, [%r8+160]
        mulq	[%rcx]
        xorq	r11, r11
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[1] * B[19]
        movq	rax, [%r8+152]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[2] * B[18]
        movq	rax, [%r8+144]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[3] * B[17]
        movq	rax, [%r8+136]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[4] * B[16]
        movq	rax, [%r8+128]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[5] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[6] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+48]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[7] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+56]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[8] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+64]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[9] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+72]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[10] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+80]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[11] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+88]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[12] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+96]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[13] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+104]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[14] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+112]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[15] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+120]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[16] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+128]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[17] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+136]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[18] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+144]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[19] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+152]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[20] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+160]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        movq	[%rsp+160], r12
        ; A[0] * B[21]
        movq	rax, [%r8+168]
        mulq	[%rcx]
        xorq	r12, r12
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[1] * B[20]
        movq	rax, [%r8+160]
        mulq	[%rcx+8]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[2] * B[19]
        movq	rax, [%r8+152]
        mulq	[%rcx+16]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[3] * B[18]
        movq	rax, [%r8+144]
        mulq	[%rcx+24]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[4] * B[17]
        movq	rax, [%r8+136]
        mulq	[%rcx+32]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[5] * B[16]
        movq	rax, [%r8+128]
        mulq	[%rcx+40]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[6] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+48]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[7] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+56]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[8] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+64]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[9] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+72]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[10] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+80]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[11] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+88]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[12] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+96]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[13] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+104]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[14] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+112]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[15] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+120]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[16] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+128]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[17] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+136]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[18] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+144]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[19] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+152]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[20] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+160]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[21] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+168]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        movq	[%rsp+168], r10
        ; A[0] * B[22]
        movq	rax, [%r8+176]
        mulq	[%rcx]
        xorq	r10, r10
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[1] * B[21]
        movq	rax, [%r8+168]
        mulq	[%rcx+8]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[2] * B[20]
        movq	rax, [%r8+160]
        mulq	[%rcx+16]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[3] * B[19]
        movq	rax, [%r8+152]
        mulq	[%rcx+24]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[4] * B[18]
        movq	rax, [%r8+144]
        mulq	[%rcx+32]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[5] * B[17]
        movq	rax, [%r8+136]
        mulq	[%rcx+40]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[6] * B[16]
        movq	rax, [%r8+128]
        mulq	[%rcx+48]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[7] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+56]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[8] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+64]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[9] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+72]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[10] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+80]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[11] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+88]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[12] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+96]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[13] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+104]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[14] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+112]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[15] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+120]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[16] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+128]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[17] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+136]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[18] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+144]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[19] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+152]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[20] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+160]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[21] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+168]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[22] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+176]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        movq	[%rsp+176], r11
        ; A[0] * B[23]
        movq	rax, [%r8+184]
        mulq	[%rcx]
        xorq	r11, r11
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[1] * B[22]
        movq	rax, [%r8+176]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[2] * B[21]
        movq	rax, [%r8+168]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[3] * B[20]
        movq	rax, [%r8+160]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[4] * B[19]
        movq	rax, [%r8+152]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[5] * B[18]
        movq	rax, [%r8+144]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[6] * B[17]
        movq	rax, [%r8+136]
        mulq	[%rcx+48]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[7] * B[16]
        movq	rax, [%r8+128]
        mulq	[%rcx+56]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[8] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+64]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[9] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+72]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[10] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+80]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[11] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+88]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[12] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+96]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[13] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+104]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[14] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+112]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[15] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+120]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[16] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+128]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[17] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+136]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[18] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+144]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[19] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+152]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[20] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+160]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[21] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+168]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[22] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+176]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[23] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+184]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        movq	[%rsp+184], r12
        ; A[1] * B[23]
        movq	rax, [%r8+184]
        mulq	[%rcx+8]
        xorq	r12, r12
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[2] * B[22]
        movq	rax, [%r8+176]
        mulq	[%rcx+16]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[3] * B[21]
        movq	rax, [%r8+168]
        mulq	[%rcx+24]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[4] * B[20]
        movq	rax, [%r8+160]
        mulq	[%rcx+32]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[5] * B[19]
        movq	rax, [%r8+152]
        mulq	[%rcx+40]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[6] * B[18]
        movq	rax, [%r8+144]
        mulq	[%rcx+48]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[7] * B[17]
        movq	rax, [%r8+136]
        mulq	[%rcx+56]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[8] * B[16]
        movq	rax, [%r8+128]
        mulq	[%rcx+64]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[9] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+72]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[10] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+80]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[11] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+88]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[12] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+96]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[13] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+104]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[14] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+112]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[15] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+120]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[16] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+128]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[17] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+136]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[18] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+144]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[19] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+152]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[20] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+160]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[21] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+168]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[22] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+176]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[23] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+184]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        movq	[%r9+192], r10
        ; A[2] * B[23]
        movq	rax, [%r8+184]
        mulq	[%rcx+16]
        xorq	r10, r10
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[3] * B[22]
        movq	rax, [%r8+176]
        mulq	[%rcx+24]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[4] * B[21]
        movq	rax, [%r8+168]
        mulq	[%rcx+32]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[5] * B[20]
        movq	rax, [%r8+160]
        mulq	[%rcx+40]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[6] * B[19]
        movq	rax, [%r8+152]
        mulq	[%rcx+48]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[7] * B[18]
        movq	rax, [%r8+144]
        mulq	[%rcx+56]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[8] * B[17]
        movq	rax, [%r8+136]
        mulq	[%rcx+64]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[9] * B[16]
        movq	rax, [%r8+128]
        mulq	[%rcx+72]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[10] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+80]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[11] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+88]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[12] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+96]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[13] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+104]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[14] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+112]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[15] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+120]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[16] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+128]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[17] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+136]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[18] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+144]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[19] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+152]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[20] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+160]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[21] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+168]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[22] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+176]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[23] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+184]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        movq	[%r9+200], r11
        ; A[3] * B[23]
        movq	rax, [%r8+184]
        mulq	[%rcx+24]
        xorq	r11, r11
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[4] * B[22]
        movq	rax, [%r8+176]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[5] * B[21]
        movq	rax, [%r8+168]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[6] * B[20]
        movq	rax, [%r8+160]
        mulq	[%rcx+48]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[7] * B[19]
        movq	rax, [%r8+152]
        mulq	[%rcx+56]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[8] * B[18]
        movq	rax, [%r8+144]
        mulq	[%rcx+64]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[9] * B[17]
        movq	rax, [%r8+136]
        mulq	[%rcx+72]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[10] * B[16]
        movq	rax, [%r8+128]
        mulq	[%rcx+80]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[11] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+88]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[12] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+96]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[13] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+104]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[14] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+112]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[15] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+120]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[16] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+128]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[17] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+136]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[18] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+144]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[19] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+152]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[20] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+160]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[21] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+168]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[22] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+176]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[23] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+184]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        movq	[%r9+208], r12
        ; A[4] * B[23]
        movq	rax, [%r8+184]
        mulq	[%rcx+32]
        xorq	r12, r12
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[5] * B[22]
        movq	rax, [%r8+176]
        mulq	[%rcx+40]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[6] * B[21]
        movq	rax, [%r8+168]
        mulq	[%rcx+48]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[7] * B[20]
        movq	rax, [%r8+160]
        mulq	[%rcx+56]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[8] * B[19]
        movq	rax, [%r8+152]
        mulq	[%rcx+64]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[9] * B[18]
        movq	rax, [%r8+144]
        mulq	[%rcx+72]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[10] * B[17]
        movq	rax, [%r8+136]
        mulq	[%rcx+80]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[11] * B[16]
        movq	rax, [%r8+128]
        mulq	[%rcx+88]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[12] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+96]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[13] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+104]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[14] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+112]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[15] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+120]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[16] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+128]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[17] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+136]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[18] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+144]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[19] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+152]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[20] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+160]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[21] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+168]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[22] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+176]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[23] * B[4]
        movq	rax, [%r8+32]
        mulq	[%rcx+184]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        movq	[%r9+216], r10
        ; A[5] * B[23]
        movq	rax, [%r8+184]
        mulq	[%rcx+40]
        xorq	r10, r10
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[6] * B[22]
        movq	rax, [%r8+176]
        mulq	[%rcx+48]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[7] * B[21]
        movq	rax, [%r8+168]
        mulq	[%rcx+56]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[8] * B[20]
        movq	rax, [%r8+160]
        mulq	[%rcx+64]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[9] * B[19]
        movq	rax, [%r8+152]
        mulq	[%rcx+72]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[10] * B[18]
        movq	rax, [%r8+144]
        mulq	[%rcx+80]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[11] * B[17]
        movq	rax, [%r8+136]
        mulq	[%rcx+88]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[12] * B[16]
        movq	rax, [%r8+128]
        mulq	[%rcx+96]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[13] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+104]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[14] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+112]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[15] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+120]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[16] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+128]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[17] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+136]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[18] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+144]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[19] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+152]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[20] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+160]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[21] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+168]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[22] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+176]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[23] * B[5]
        movq	rax, [%r8+40]
        mulq	[%rcx+184]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        movq	[%r9+224], r11
        ; A[6] * B[23]
        movq	rax, [%r8+184]
        mulq	[%rcx+48]
        xorq	r11, r11
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[7] * B[22]
        movq	rax, [%r8+176]
        mulq	[%rcx+56]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[8] * B[21]
        movq	rax, [%r8+168]
        mulq	[%rcx+64]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[9] * B[20]
        movq	rax, [%r8+160]
        mulq	[%rcx+72]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[10] * B[19]
        movq	rax, [%r8+152]
        mulq	[%rcx+80]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[11] * B[18]
        movq	rax, [%r8+144]
        mulq	[%rcx+88]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[12] * B[17]
        movq	rax, [%r8+136]
        mulq	[%rcx+96]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[13] * B[16]
        movq	rax, [%r8+128]
        mulq	[%rcx+104]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[14] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+112]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[15] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+120]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[16] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+128]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[17] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+136]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[18] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+144]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[19] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+152]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[20] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+160]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[21] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+168]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[22] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+176]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[23] * B[6]
        movq	rax, [%r8+48]
        mulq	[%rcx+184]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        movq	[%r9+232], r12
        ; A[7] * B[23]
        movq	rax, [%r8+184]
        mulq	[%rcx+56]
        xorq	r12, r12
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[8] * B[22]
        movq	rax, [%r8+176]
        mulq	[%rcx+64]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[9] * B[21]
        movq	rax, [%r8+168]
        mulq	[%rcx+72]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[10] * B[20]
        movq	rax, [%r8+160]
        mulq	[%rcx+80]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[11] * B[19]
        movq	rax, [%r8+152]
        mulq	[%rcx+88]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[12] * B[18]
        movq	rax, [%r8+144]
        mulq	[%rcx+96]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[13] * B[17]
        movq	rax, [%r8+136]
        mulq	[%rcx+104]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[14] * B[16]
        movq	rax, [%r8+128]
        mulq	[%rcx+112]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[15] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+120]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[16] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+128]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[17] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+136]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[18] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+144]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[19] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+152]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[20] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+160]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[21] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+168]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[22] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+176]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[23] * B[7]
        movq	rax, [%r8+56]
        mulq	[%rcx+184]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        movq	[%r9+240], r10
        ; A[8] * B[23]
        movq	rax, [%r8+184]
        mulq	[%rcx+64]
        xorq	r10, r10
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[9] * B[22]
        movq	rax, [%r8+176]
        mulq	[%rcx+72]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[10] * B[21]
        movq	rax, [%r8+168]
        mulq	[%rcx+80]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[11] * B[20]
        movq	rax, [%r8+160]
        mulq	[%rcx+88]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[12] * B[19]
        movq	rax, [%r8+152]
        mulq	[%rcx+96]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[13] * B[18]
        movq	rax, [%r8+144]
        mulq	[%rcx+104]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[14] * B[17]
        movq	rax, [%r8+136]
        mulq	[%rcx+112]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[15] * B[16]
        movq	rax, [%r8+128]
        mulq	[%rcx+120]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[16] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+128]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[17] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+136]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[18] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+144]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[19] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+152]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[20] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+160]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[21] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+168]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[22] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+176]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[23] * B[8]
        movq	rax, [%r8+64]
        mulq	[%rcx+184]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        movq	[%r9+248], r11
        ; A[9] * B[23]
        movq	rax, [%r8+184]
        mulq	[%rcx+72]
        xorq	r11, r11
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[10] * B[22]
        movq	rax, [%r8+176]
        mulq	[%rcx+80]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[11] * B[21]
        movq	rax, [%r8+168]
        mulq	[%rcx+88]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[12] * B[20]
        movq	rax, [%r8+160]
        mulq	[%rcx+96]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[13] * B[19]
        movq	rax, [%r8+152]
        mulq	[%rcx+104]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[14] * B[18]
        movq	rax, [%r8+144]
        mulq	[%rcx+112]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[15] * B[17]
        movq	rax, [%r8+136]
        mulq	[%rcx+120]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[16] * B[16]
        movq	rax, [%r8+128]
        mulq	[%rcx+128]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[17] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+136]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[18] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+144]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[19] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+152]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[20] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+160]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[21] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+168]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[22] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+176]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[23] * B[9]
        movq	rax, [%r8+72]
        mulq	[%rcx+184]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        movq	[%r9+256], r12
        ; A[10] * B[23]
        movq	rax, [%r8+184]
        mulq	[%rcx+80]
        xorq	r12, r12
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[11] * B[22]
        movq	rax, [%r8+176]
        mulq	[%rcx+88]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[12] * B[21]
        movq	rax, [%r8+168]
        mulq	[%rcx+96]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[13] * B[20]
        movq	rax, [%r8+160]
        mulq	[%rcx+104]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[14] * B[19]
        movq	rax, [%r8+152]
        mulq	[%rcx+112]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[15] * B[18]
        movq	rax, [%r8+144]
        mulq	[%rcx+120]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[16] * B[17]
        movq	rax, [%r8+136]
        mulq	[%rcx+128]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[17] * B[16]
        movq	rax, [%r8+128]
        mulq	[%rcx+136]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[18] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+144]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[19] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+152]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[20] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+160]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[21] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+168]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[22] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+176]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[23] * B[10]
        movq	rax, [%r8+80]
        mulq	[%rcx+184]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        movq	[%r9+264], r10
        ; A[11] * B[23]
        movq	rax, [%r8+184]
        mulq	[%rcx+88]
        xorq	r10, r10
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[12] * B[22]
        movq	rax, [%r8+176]
        mulq	[%rcx+96]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[13] * B[21]
        movq	rax, [%r8+168]
        mulq	[%rcx+104]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[14] * B[20]
        movq	rax, [%r8+160]
        mulq	[%rcx+112]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[15] * B[19]
        movq	rax, [%r8+152]
        mulq	[%rcx+120]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[16] * B[18]
        movq	rax, [%r8+144]
        mulq	[%rcx+128]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[17] * B[17]
        movq	rax, [%r8+136]
        mulq	[%rcx+136]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[18] * B[16]
        movq	rax, [%r8+128]
        mulq	[%rcx+144]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[19] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+152]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[20] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+160]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[21] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+168]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[22] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+176]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[23] * B[11]
        movq	rax, [%r8+88]
        mulq	[%rcx+184]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        movq	[%r9+272], r11
        ; A[12] * B[23]
        movq	rax, [%r8+184]
        mulq	[%rcx+96]
        xorq	r11, r11
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[13] * B[22]
        movq	rax, [%r8+176]
        mulq	[%rcx+104]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[14] * B[21]
        movq	rax, [%r8+168]
        mulq	[%rcx+112]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[15] * B[20]
        movq	rax, [%r8+160]
        mulq	[%rcx+120]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[16] * B[19]
        movq	rax, [%r8+152]
        mulq	[%rcx+128]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[17] * B[18]
        movq	rax, [%r8+144]
        mulq	[%rcx+136]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[18] * B[17]
        movq	rax, [%r8+136]
        mulq	[%rcx+144]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[19] * B[16]
        movq	rax, [%r8+128]
        mulq	[%rcx+152]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[20] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+160]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[21] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+168]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[22] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+176]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[23] * B[12]
        movq	rax, [%r8+96]
        mulq	[%rcx+184]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        movq	[%r9+280], r12
        ; A[13] * B[23]
        movq	rax, [%r8+184]
        mulq	[%rcx+104]
        xorq	r12, r12
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[14] * B[22]
        movq	rax, [%r8+176]
        mulq	[%rcx+112]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[15] * B[21]
        movq	rax, [%r8+168]
        mulq	[%rcx+120]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[16] * B[20]
        movq	rax, [%r8+160]
        mulq	[%rcx+128]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[17] * B[19]
        movq	rax, [%r8+152]
        mulq	[%rcx+136]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[18] * B[18]
        movq	rax, [%r8+144]
        mulq	[%rcx+144]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[19] * B[17]
        movq	rax, [%r8+136]
        mulq	[%rcx+152]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[20] * B[16]
        movq	rax, [%r8+128]
        mulq	[%rcx+160]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[21] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+168]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[22] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+176]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[23] * B[13]
        movq	rax, [%r8+104]
        mulq	[%rcx+184]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        movq	[%r9+288], r10
        ; A[14] * B[23]
        movq	rax, [%r8+184]
        mulq	[%rcx+112]
        xorq	r10, r10
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[15] * B[22]
        movq	rax, [%r8+176]
        mulq	[%rcx+120]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[16] * B[21]
        movq	rax, [%r8+168]
        mulq	[%rcx+128]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[17] * B[20]
        movq	rax, [%r8+160]
        mulq	[%rcx+136]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[18] * B[19]
        movq	rax, [%r8+152]
        mulq	[%rcx+144]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[19] * B[18]
        movq	rax, [%r8+144]
        mulq	[%rcx+152]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[20] * B[17]
        movq	rax, [%r8+136]
        mulq	[%rcx+160]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[21] * B[16]
        movq	rax, [%r8+128]
        mulq	[%rcx+168]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[22] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+176]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[23] * B[14]
        movq	rax, [%r8+112]
        mulq	[%rcx+184]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        movq	[%r9+296], r11
        ; A[15] * B[23]
        movq	rax, [%r8+184]
        mulq	[%rcx+120]
        xorq	r11, r11
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[16] * B[22]
        movq	rax, [%r8+176]
        mulq	[%rcx+128]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[17] * B[21]
        movq	rax, [%r8+168]
        mulq	[%rcx+136]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[18] * B[20]
        movq	rax, [%r8+160]
        mulq	[%rcx+144]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[19] * B[19]
        movq	rax, [%r8+152]
        mulq	[%rcx+152]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[20] * B[18]
        movq	rax, [%r8+144]
        mulq	[%rcx+160]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[21] * B[17]
        movq	rax, [%r8+136]
        mulq	[%rcx+168]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[22] * B[16]
        movq	rax, [%r8+128]
        mulq	[%rcx+176]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[23] * B[15]
        movq	rax, [%r8+120]
        mulq	[%rcx+184]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        movq	[%r9+304], r12
        ; A[16] * B[23]
        movq	rax, [%r8+184]
        mulq	[%rcx+128]
        xorq	r12, r12
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[17] * B[22]
        movq	rax, [%r8+176]
        mulq	[%rcx+136]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[18] * B[21]
        movq	rax, [%r8+168]
        mulq	[%rcx+144]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[19] * B[20]
        movq	rax, [%r8+160]
        mulq	[%rcx+152]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[20] * B[19]
        movq	rax, [%r8+152]
        mulq	[%rcx+160]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[21] * B[18]
        movq	rax, [%r8+144]
        mulq	[%rcx+168]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[22] * B[17]
        movq	rax, [%r8+136]
        mulq	[%rcx+176]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[23] * B[16]
        movq	rax, [%r8+128]
        mulq	[%rcx+184]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        movq	[%r9+312], r10
        ; A[17] * B[23]
        movq	rax, [%r8+184]
        mulq	[%rcx+136]
        xorq	r10, r10
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[18] * B[22]
        movq	rax, [%r8+176]
        mulq	[%rcx+144]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[19] * B[21]
        movq	rax, [%r8+168]
        mulq	[%rcx+152]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[20] * B[20]
        movq	rax, [%r8+160]
        mulq	[%rcx+160]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[21] * B[19]
        movq	rax, [%r8+152]
        mulq	[%rcx+168]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[22] * B[18]
        movq	rax, [%r8+144]
        mulq	[%rcx+176]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[23] * B[17]
        movq	rax, [%r8+136]
        mulq	[%rcx+184]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        movq	[%r9+320], r11
        ; A[18] * B[23]
        movq	rax, [%r8+184]
        mulq	[%rcx+144]
        xorq	r11, r11
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[19] * B[22]
        movq	rax, [%r8+176]
        mulq	[%rcx+152]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[20] * B[21]
        movq	rax, [%r8+168]
        mulq	[%rcx+160]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[21] * B[20]
        movq	rax, [%r8+160]
        mulq	[%rcx+168]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[22] * B[19]
        movq	rax, [%r8+152]
        mulq	[%rcx+176]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[23] * B[18]
        movq	rax, [%r8+144]
        mulq	[%rcx+184]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        movq	[%r9+328], r12
        ; A[19] * B[23]
        movq	rax, [%r8+184]
        mulq	[%rcx+152]
        xorq	r12, r12
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[20] * B[22]
        movq	rax, [%r8+176]
        mulq	[%rcx+160]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[21] * B[21]
        movq	rax, [%r8+168]
        mulq	[%rcx+168]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[22] * B[20]
        movq	rax, [%r8+160]
        mulq	[%rcx+176]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[23] * B[19]
        movq	rax, [%r8+152]
        mulq	[%rcx+184]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        movq	[%r9+336], r10
        ; A[20] * B[23]
        movq	rax, [%r8+184]
        mulq	[%rcx+160]
        xorq	r10, r10
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[21] * B[22]
        movq	rax, [%r8+176]
        mulq	[%rcx+168]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[22] * B[21]
        movq	rax, [%r8+168]
        mulq	[%rcx+176]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[23] * B[20]
        movq	rax, [%r8+160]
        mulq	[%rcx+184]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        movq	[%r9+344], r11
        ; A[21] * B[23]
        movq	rax, [%r8+184]
        mulq	[%rcx+168]
        xorq	r11, r11
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[22] * B[22]
        movq	rax, [%r8+176]
        mulq	[%rcx+176]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[23] * B[21]
        movq	rax, [%r8+168]
        mulq	[%rcx+184]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        movq	[%r9+352], r12
        ; A[22] * B[23]
        movq	rax, [%r8+184]
        mulq	[%rcx+176]
        xorq	r12, r12
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[23] * B[22]
        movq	rax, [%r8+176]
        mulq	[%rcx+184]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        movq	[%r9+360], r10
        ; A[23] * B[23]
        movq	rax, [%r8+184]
        mulq	[%rcx+184]
        addq	r11, rax
        adcq	r12, rdx
        movq	[%r9+368], r11
        movq	[%r9+376], r12
        movq	rax, [%rsp]
        movq	rdx, [%rsp+8]
        movq	r10, [%rsp+16]
        movq	r11, [%rsp+24]
        movq	[%r9], rax
        movq	[%r9+8], rdx
        movq	[%r9+16], r10
        movq	[%r9+24], r11
        movq	rax, [%rsp+32]
        movq	rdx, [%rsp+40]
        movq	r10, [%rsp+48]
        movq	r11, [%rsp+56]
        movq	[%r9+32], rax
        movq	[%r9+40], rdx
        movq	[%r9+48], r10
        movq	[%r9+56], r11
        movq	rax, [%rsp+64]
        movq	rdx, [%rsp+72]
        movq	r10, [%rsp+80]
        movq	r11, [%rsp+88]
        movq	[%r9+64], rax
        movq	[%r9+72], rdx
        movq	[%r9+80], r10
        movq	[%r9+88], r11
        movq	rax, [%rsp+96]
        movq	rdx, [%rsp+104]
        movq	r10, [%rsp+112]
        movq	r11, [%rsp+120]
        movq	[%r9+96], rax
        movq	[%r9+104], rdx
        movq	[%r9+112], r10
        movq	[%r9+120], r11
        movq	rax, [%rsp+128]
        movq	rdx, [%rsp+136]
        movq	r10, [%rsp+144]
        movq	r11, [%rsp+152]
        movq	[%r9+128], rax
        movq	[%r9+136], rdx
        movq	[%r9+144], r10
        movq	[%r9+152], r11
        movq	rax, [%rsp+160]
        movq	rdx, [%rsp+168]
        movq	r10, [%rsp+176]
        movq	r11, [%rsp+184]
        movq	[%r9+160], rax
        movq	[%r9+168], rdx
        movq	[%r9+176], r10
        movq	[%r9+184], r11
        addq	rsp, 192
        pop	r12
        repz retq
sp_3072_mul_24 ENDP
; /* Square a and put result in r. (r = a * a)
;  *
;  * r  A single precision integer.
;  * a  A single precision integer.
;  */
sp_3072_sqr_24 PROC
        movq	rcx, rdx
        movq	r8, rcx
        push	r12
        push	r13
        push	r14
        subq	rsp, 192
        ; A[0] * A[0]
        movq	rax, [%rcx]
        mulq	rax
        xorq	r11, r11
        movq	[%rsp], rax
        movq	r10, rdx
        ; A[0] * A[1]
        movq	rax, [%rcx+8]
        mulq	[%rcx]
        xorq	r9, r9
        addq	r10, rax
        adcq	r11, rdx
        adcq	r9, 0
        addq	r10, rax
        adcq	r11, rdx
        adcq	r9, 0
        movq	[%rsp+8], r10
        ; A[0] * A[2]
        movq	rax, [%rcx+16]
        mulq	[%rcx]
        xorq	r10, r10
        addq	r11, rax
        adcq	r9, rdx
        adcq	r10, 0
        addq	r11, rax
        adcq	r9, rdx
        adcq	r10, 0
        ; A[1] * A[1]
        movq	rax, [%rcx+8]
        mulq	rax
        addq	r11, rax
        adcq	r9, rdx
        adcq	r10, 0
        movq	[%rsp+16], r11
        ; A[0] * A[3]
        movq	rax, [%rcx+24]
        mulq	[%rcx]
        xorq	r11, r11
        addq	r9, rax
        adcq	r10, rdx
        adcq	r11, 0
        addq	r9, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[1] * A[2]
        movq	rax, [%rcx+16]
        mulq	[%rcx+8]
        addq	r9, rax
        adcq	r10, rdx
        adcq	r11, 0
        addq	r9, rax
        adcq	r10, rdx
        adcq	r11, 0
        movq	[%rsp+24], r9
        ; A[0] * A[4]
        movq	rax, [%rcx+32]
        mulq	[%rcx]
        xorq	r9, r9
        addq	r10, rax
        adcq	r11, rdx
        adcq	r9, 0
        addq	r10, rax
        adcq	r11, rdx
        adcq	r9, 0
        ; A[1] * A[3]
        movq	rax, [%rcx+24]
        mulq	[%rcx+8]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r9, 0
        addq	r10, rax
        adcq	r11, rdx
        adcq	r9, 0
        ; A[2] * A[2]
        movq	rax, [%rcx+16]
        mulq	rax
        addq	r10, rax
        adcq	r11, rdx
        adcq	r9, 0
        movq	[%rsp+32], r10
        ; A[0] * A[5]
        movq	rax, [%rcx+40]
        mulq	[%rcx]
        xorq	r10, r10
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[1] * A[4]
        movq	rax, [%rcx+32]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[2] * A[3]
        movq	rax, [%rcx+24]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r11, r12
        adcq	r9, r13
        adcq	r10, r14
        movq	[%rsp+40], r11
        ; A[0] * A[6]
        movq	rax, [%rcx+48]
        mulq	[%rcx]
        xorq	r11, r11
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[1] * A[5]
        movq	rax, [%rcx+40]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[2] * A[4]
        movq	rax, [%rcx+32]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[3] * A[3]
        movq	rax, [%rcx+24]
        mulq	rax
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r9, r12
        adcq	r10, r13
        adcq	r11, r14
        movq	[%rsp+48], r9
        ; A[0] * A[7]
        movq	rax, [%rcx+56]
        mulq	[%rcx]
        xorq	r9, r9
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[1] * A[6]
        movq	rax, [%rcx+48]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[2] * A[5]
        movq	rax, [%rcx+40]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[3] * A[4]
        movq	rax, [%rcx+32]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r10, r12
        adcq	r11, r13
        adcq	r9, r14
        movq	[%rsp+56], r10
        ; A[0] * A[8]
        movq	rax, [%rcx+64]
        mulq	[%rcx]
        xorq	r10, r10
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[1] * A[7]
        movq	rax, [%rcx+56]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[2] * A[6]
        movq	rax, [%rcx+48]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[3] * A[5]
        movq	rax, [%rcx+40]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[4] * A[4]
        movq	rax, [%rcx+32]
        mulq	rax
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r11, r12
        adcq	r9, r13
        adcq	r10, r14
        movq	[%rsp+64], r11
        ; A[0] * A[9]
        movq	rax, [%rcx+72]
        mulq	[%rcx]
        xorq	r11, r11
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[1] * A[8]
        movq	rax, [%rcx+64]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[2] * A[7]
        movq	rax, [%rcx+56]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[3] * A[6]
        movq	rax, [%rcx+48]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[4] * A[5]
        movq	rax, [%rcx+40]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r9, r12
        adcq	r10, r13
        adcq	r11, r14
        movq	[%rsp+72], r9
        ; A[0] * A[10]
        movq	rax, [%rcx+80]
        mulq	[%rcx]
        xorq	r9, r9
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[1] * A[9]
        movq	rax, [%rcx+72]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[2] * A[8]
        movq	rax, [%rcx+64]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[3] * A[7]
        movq	rax, [%rcx+56]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[4] * A[6]
        movq	rax, [%rcx+48]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[5] * A[5]
        movq	rax, [%rcx+40]
        mulq	rax
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r10, r12
        adcq	r11, r13
        adcq	r9, r14
        movq	[%rsp+80], r10
        ; A[0] * A[11]
        movq	rax, [%rcx+88]
        mulq	[%rcx]
        xorq	r10, r10
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[1] * A[10]
        movq	rax, [%rcx+80]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[2] * A[9]
        movq	rax, [%rcx+72]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[3] * A[8]
        movq	rax, [%rcx+64]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[4] * A[7]
        movq	rax, [%rcx+56]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[5] * A[6]
        movq	rax, [%rcx+48]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r11, r12
        adcq	r9, r13
        adcq	r10, r14
        movq	[%rsp+88], r11
        ; A[0] * A[12]
        movq	rax, [%rcx+96]
        mulq	[%rcx]
        xorq	r11, r11
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[1] * A[11]
        movq	rax, [%rcx+88]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[2] * A[10]
        movq	rax, [%rcx+80]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[3] * A[9]
        movq	rax, [%rcx+72]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[4] * A[8]
        movq	rax, [%rcx+64]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[5] * A[7]
        movq	rax, [%rcx+56]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[6] * A[6]
        movq	rax, [%rcx+48]
        mulq	rax
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r9, r12
        adcq	r10, r13
        adcq	r11, r14
        movq	[%rsp+96], r9
        ; A[0] * A[13]
        movq	rax, [%rcx+104]
        mulq	[%rcx]
        xorq	r9, r9
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[1] * A[12]
        movq	rax, [%rcx+96]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[2] * A[11]
        movq	rax, [%rcx+88]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[3] * A[10]
        movq	rax, [%rcx+80]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[4] * A[9]
        movq	rax, [%rcx+72]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[5] * A[8]
        movq	rax, [%rcx+64]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[6] * A[7]
        movq	rax, [%rcx+56]
        mulq	[%rcx+48]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r10, r12
        adcq	r11, r13
        adcq	r9, r14
        movq	[%rsp+104], r10
        ; A[0] * A[14]
        movq	rax, [%rcx+112]
        mulq	[%rcx]
        xorq	r10, r10
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[1] * A[13]
        movq	rax, [%rcx+104]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[2] * A[12]
        movq	rax, [%rcx+96]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[3] * A[11]
        movq	rax, [%rcx+88]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[4] * A[10]
        movq	rax, [%rcx+80]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[5] * A[9]
        movq	rax, [%rcx+72]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[6] * A[8]
        movq	rax, [%rcx+64]
        mulq	[%rcx+48]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[7] * A[7]
        movq	rax, [%rcx+56]
        mulq	rax
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r11, r12
        adcq	r9, r13
        adcq	r10, r14
        movq	[%rsp+112], r11
        ; A[0] * A[15]
        movq	rax, [%rcx+120]
        mulq	[%rcx]
        xorq	r11, r11
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[1] * A[14]
        movq	rax, [%rcx+112]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[2] * A[13]
        movq	rax, [%rcx+104]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[3] * A[12]
        movq	rax, [%rcx+96]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[4] * A[11]
        movq	rax, [%rcx+88]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[5] * A[10]
        movq	rax, [%rcx+80]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[6] * A[9]
        movq	rax, [%rcx+72]
        mulq	[%rcx+48]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[7] * A[8]
        movq	rax, [%rcx+64]
        mulq	[%rcx+56]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r9, r12
        adcq	r10, r13
        adcq	r11, r14
        movq	[%rsp+120], r9
        ; A[0] * A[16]
        movq	rax, [%rcx+128]
        mulq	[%rcx]
        xorq	r9, r9
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[1] * A[15]
        movq	rax, [%rcx+120]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[2] * A[14]
        movq	rax, [%rcx+112]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[3] * A[13]
        movq	rax, [%rcx+104]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[4] * A[12]
        movq	rax, [%rcx+96]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[5] * A[11]
        movq	rax, [%rcx+88]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[6] * A[10]
        movq	rax, [%rcx+80]
        mulq	[%rcx+48]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[7] * A[9]
        movq	rax, [%rcx+72]
        mulq	[%rcx+56]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[8] * A[8]
        movq	rax, [%rcx+64]
        mulq	rax
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r10, r12
        adcq	r11, r13
        adcq	r9, r14
        movq	[%rsp+128], r10
        ; A[0] * A[17]
        movq	rax, [%rcx+136]
        mulq	[%rcx]
        xorq	r10, r10
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[1] * A[16]
        movq	rax, [%rcx+128]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[2] * A[15]
        movq	rax, [%rcx+120]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[3] * A[14]
        movq	rax, [%rcx+112]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[4] * A[13]
        movq	rax, [%rcx+104]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[5] * A[12]
        movq	rax, [%rcx+96]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[6] * A[11]
        movq	rax, [%rcx+88]
        mulq	[%rcx+48]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[7] * A[10]
        movq	rax, [%rcx+80]
        mulq	[%rcx+56]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[8] * A[9]
        movq	rax, [%rcx+72]
        mulq	[%rcx+64]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r11, r12
        adcq	r9, r13
        adcq	r10, r14
        movq	[%rsp+136], r11
        ; A[0] * A[18]
        movq	rax, [%rcx+144]
        mulq	[%rcx]
        xorq	r11, r11
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[1] * A[17]
        movq	rax, [%rcx+136]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[2] * A[16]
        movq	rax, [%rcx+128]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[3] * A[15]
        movq	rax, [%rcx+120]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[4] * A[14]
        movq	rax, [%rcx+112]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[5] * A[13]
        movq	rax, [%rcx+104]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[6] * A[12]
        movq	rax, [%rcx+96]
        mulq	[%rcx+48]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[7] * A[11]
        movq	rax, [%rcx+88]
        mulq	[%rcx+56]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[8] * A[10]
        movq	rax, [%rcx+80]
        mulq	[%rcx+64]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[9] * A[9]
        movq	rax, [%rcx+72]
        mulq	rax
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r9, r12
        adcq	r10, r13
        adcq	r11, r14
        movq	[%rsp+144], r9
        ; A[0] * A[19]
        movq	rax, [%rcx+152]
        mulq	[%rcx]
        xorq	r9, r9
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[1] * A[18]
        movq	rax, [%rcx+144]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[2] * A[17]
        movq	rax, [%rcx+136]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[3] * A[16]
        movq	rax, [%rcx+128]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[4] * A[15]
        movq	rax, [%rcx+120]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[5] * A[14]
        movq	rax, [%rcx+112]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[6] * A[13]
        movq	rax, [%rcx+104]
        mulq	[%rcx+48]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[7] * A[12]
        movq	rax, [%rcx+96]
        mulq	[%rcx+56]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[8] * A[11]
        movq	rax, [%rcx+88]
        mulq	[%rcx+64]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[9] * A[10]
        movq	rax, [%rcx+80]
        mulq	[%rcx+72]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r10, r12
        adcq	r11, r13
        adcq	r9, r14
        movq	[%rsp+152], r10
        ; A[0] * A[20]
        movq	rax, [%rcx+160]
        mulq	[%rcx]
        xorq	r10, r10
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[1] * A[19]
        movq	rax, [%rcx+152]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[2] * A[18]
        movq	rax, [%rcx+144]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[3] * A[17]
        movq	rax, [%rcx+136]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[4] * A[16]
        movq	rax, [%rcx+128]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[5] * A[15]
        movq	rax, [%rcx+120]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[6] * A[14]
        movq	rax, [%rcx+112]
        mulq	[%rcx+48]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[7] * A[13]
        movq	rax, [%rcx+104]
        mulq	[%rcx+56]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[8] * A[12]
        movq	rax, [%rcx+96]
        mulq	[%rcx+64]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[9] * A[11]
        movq	rax, [%rcx+88]
        mulq	[%rcx+72]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[10] * A[10]
        movq	rax, [%rcx+80]
        mulq	rax
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r11, r12
        adcq	r9, r13
        adcq	r10, r14
        movq	[%rsp+160], r11
        ; A[0] * A[21]
        movq	rax, [%rcx+168]
        mulq	[%rcx]
        xorq	r11, r11
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[1] * A[20]
        movq	rax, [%rcx+160]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[2] * A[19]
        movq	rax, [%rcx+152]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[3] * A[18]
        movq	rax, [%rcx+144]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[4] * A[17]
        movq	rax, [%rcx+136]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[5] * A[16]
        movq	rax, [%rcx+128]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[6] * A[15]
        movq	rax, [%rcx+120]
        mulq	[%rcx+48]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[7] * A[14]
        movq	rax, [%rcx+112]
        mulq	[%rcx+56]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[8] * A[13]
        movq	rax, [%rcx+104]
        mulq	[%rcx+64]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[9] * A[12]
        movq	rax, [%rcx+96]
        mulq	[%rcx+72]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[10] * A[11]
        movq	rax, [%rcx+88]
        mulq	[%rcx+80]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r9, r12
        adcq	r10, r13
        adcq	r11, r14
        movq	[%rsp+168], r9
        ; A[0] * A[22]
        movq	rax, [%rcx+176]
        mulq	[%rcx]
        xorq	r9, r9
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[1] * A[21]
        movq	rax, [%rcx+168]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[2] * A[20]
        movq	rax, [%rcx+160]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[3] * A[19]
        movq	rax, [%rcx+152]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[4] * A[18]
        movq	rax, [%rcx+144]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[5] * A[17]
        movq	rax, [%rcx+136]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[6] * A[16]
        movq	rax, [%rcx+128]
        mulq	[%rcx+48]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[7] * A[15]
        movq	rax, [%rcx+120]
        mulq	[%rcx+56]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[8] * A[14]
        movq	rax, [%rcx+112]
        mulq	[%rcx+64]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[9] * A[13]
        movq	rax, [%rcx+104]
        mulq	[%rcx+72]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[10] * A[12]
        movq	rax, [%rcx+96]
        mulq	[%rcx+80]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[11] * A[11]
        movq	rax, [%rcx+88]
        mulq	rax
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r10, r12
        adcq	r11, r13
        adcq	r9, r14
        movq	[%rsp+176], r10
        ; A[0] * A[23]
        movq	rax, [%rcx+184]
        mulq	[%rcx]
        xorq	r10, r10
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[1] * A[22]
        movq	rax, [%rcx+176]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[2] * A[21]
        movq	rax, [%rcx+168]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[3] * A[20]
        movq	rax, [%rcx+160]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[4] * A[19]
        movq	rax, [%rcx+152]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[5] * A[18]
        movq	rax, [%rcx+144]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[6] * A[17]
        movq	rax, [%rcx+136]
        mulq	[%rcx+48]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[7] * A[16]
        movq	rax, [%rcx+128]
        mulq	[%rcx+56]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[8] * A[15]
        movq	rax, [%rcx+120]
        mulq	[%rcx+64]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[9] * A[14]
        movq	rax, [%rcx+112]
        mulq	[%rcx+72]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[10] * A[13]
        movq	rax, [%rcx+104]
        mulq	[%rcx+80]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[11] * A[12]
        movq	rax, [%rcx+96]
        mulq	[%rcx+88]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r11, r12
        adcq	r9, r13
        adcq	r10, r14
        movq	[%rsp+184], r11
        ; A[1] * A[23]
        movq	rax, [%rcx+184]
        mulq	[%rcx+8]
        xorq	r11, r11
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[2] * A[22]
        movq	rax, [%rcx+176]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[3] * A[21]
        movq	rax, [%rcx+168]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[4] * A[20]
        movq	rax, [%rcx+160]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[5] * A[19]
        movq	rax, [%rcx+152]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[6] * A[18]
        movq	rax, [%rcx+144]
        mulq	[%rcx+48]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[7] * A[17]
        movq	rax, [%rcx+136]
        mulq	[%rcx+56]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[8] * A[16]
        movq	rax, [%rcx+128]
        mulq	[%rcx+64]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[9] * A[15]
        movq	rax, [%rcx+120]
        mulq	[%rcx+72]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[10] * A[14]
        movq	rax, [%rcx+112]
        mulq	[%rcx+80]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[11] * A[13]
        movq	rax, [%rcx+104]
        mulq	[%rcx+88]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[12] * A[12]
        movq	rax, [%rcx+96]
        mulq	rax
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r9, r12
        adcq	r10, r13
        adcq	r11, r14
        movq	[%r8+192], r9
        ; A[2] * A[23]
        movq	rax, [%rcx+184]
        mulq	[%rcx+16]
        xorq	r9, r9
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[3] * A[22]
        movq	rax, [%rcx+176]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[4] * A[21]
        movq	rax, [%rcx+168]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[5] * A[20]
        movq	rax, [%rcx+160]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[6] * A[19]
        movq	rax, [%rcx+152]
        mulq	[%rcx+48]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[7] * A[18]
        movq	rax, [%rcx+144]
        mulq	[%rcx+56]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[8] * A[17]
        movq	rax, [%rcx+136]
        mulq	[%rcx+64]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[9] * A[16]
        movq	rax, [%rcx+128]
        mulq	[%rcx+72]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[10] * A[15]
        movq	rax, [%rcx+120]
        mulq	[%rcx+80]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[11] * A[14]
        movq	rax, [%rcx+112]
        mulq	[%rcx+88]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[12] * A[13]
        movq	rax, [%rcx+104]
        mulq	[%rcx+96]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r10, r12
        adcq	r11, r13
        adcq	r9, r14
        movq	[%r8+200], r10
        ; A[3] * A[23]
        movq	rax, [%rcx+184]
        mulq	[%rcx+24]
        xorq	r10, r10
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[4] * A[22]
        movq	rax, [%rcx+176]
        mulq	[%rcx+32]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[5] * A[21]
        movq	rax, [%rcx+168]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[6] * A[20]
        movq	rax, [%rcx+160]
        mulq	[%rcx+48]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[7] * A[19]
        movq	rax, [%rcx+152]
        mulq	[%rcx+56]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[8] * A[18]
        movq	rax, [%rcx+144]
        mulq	[%rcx+64]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[9] * A[17]
        movq	rax, [%rcx+136]
        mulq	[%rcx+72]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[10] * A[16]
        movq	rax, [%rcx+128]
        mulq	[%rcx+80]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[11] * A[15]
        movq	rax, [%rcx+120]
        mulq	[%rcx+88]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[12] * A[14]
        movq	rax, [%rcx+112]
        mulq	[%rcx+96]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[13] * A[13]
        movq	rax, [%rcx+104]
        mulq	rax
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r11, r12
        adcq	r9, r13
        adcq	r10, r14
        movq	[%r8+208], r11
        ; A[4] * A[23]
        movq	rax, [%rcx+184]
        mulq	[%rcx+32]
        xorq	r11, r11
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[5] * A[22]
        movq	rax, [%rcx+176]
        mulq	[%rcx+40]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[6] * A[21]
        movq	rax, [%rcx+168]
        mulq	[%rcx+48]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[7] * A[20]
        movq	rax, [%rcx+160]
        mulq	[%rcx+56]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[8] * A[19]
        movq	rax, [%rcx+152]
        mulq	[%rcx+64]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[9] * A[18]
        movq	rax, [%rcx+144]
        mulq	[%rcx+72]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[10] * A[17]
        movq	rax, [%rcx+136]
        mulq	[%rcx+80]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[11] * A[16]
        movq	rax, [%rcx+128]
        mulq	[%rcx+88]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[12] * A[15]
        movq	rax, [%rcx+120]
        mulq	[%rcx+96]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[13] * A[14]
        movq	rax, [%rcx+112]
        mulq	[%rcx+104]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r9, r12
        adcq	r10, r13
        adcq	r11, r14
        movq	[%r8+216], r9
        ; A[5] * A[23]
        movq	rax, [%rcx+184]
        mulq	[%rcx+40]
        xorq	r9, r9
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[6] * A[22]
        movq	rax, [%rcx+176]
        mulq	[%rcx+48]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[7] * A[21]
        movq	rax, [%rcx+168]
        mulq	[%rcx+56]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[8] * A[20]
        movq	rax, [%rcx+160]
        mulq	[%rcx+64]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[9] * A[19]
        movq	rax, [%rcx+152]
        mulq	[%rcx+72]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[10] * A[18]
        movq	rax, [%rcx+144]
        mulq	[%rcx+80]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[11] * A[17]
        movq	rax, [%rcx+136]
        mulq	[%rcx+88]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[12] * A[16]
        movq	rax, [%rcx+128]
        mulq	[%rcx+96]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[13] * A[15]
        movq	rax, [%rcx+120]
        mulq	[%rcx+104]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[14] * A[14]
        movq	rax, [%rcx+112]
        mulq	rax
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r10, r12
        adcq	r11, r13
        adcq	r9, r14
        movq	[%r8+224], r10
        ; A[6] * A[23]
        movq	rax, [%rcx+184]
        mulq	[%rcx+48]
        xorq	r10, r10
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[7] * A[22]
        movq	rax, [%rcx+176]
        mulq	[%rcx+56]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[8] * A[21]
        movq	rax, [%rcx+168]
        mulq	[%rcx+64]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[9] * A[20]
        movq	rax, [%rcx+160]
        mulq	[%rcx+72]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[10] * A[19]
        movq	rax, [%rcx+152]
        mulq	[%rcx+80]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[11] * A[18]
        movq	rax, [%rcx+144]
        mulq	[%rcx+88]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[12] * A[17]
        movq	rax, [%rcx+136]
        mulq	[%rcx+96]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[13] * A[16]
        movq	rax, [%rcx+128]
        mulq	[%rcx+104]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[14] * A[15]
        movq	rax, [%rcx+120]
        mulq	[%rcx+112]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r11, r12
        adcq	r9, r13
        adcq	r10, r14
        movq	[%r8+232], r11
        ; A[7] * A[23]
        movq	rax, [%rcx+184]
        mulq	[%rcx+56]
        xorq	r11, r11
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[8] * A[22]
        movq	rax, [%rcx+176]
        mulq	[%rcx+64]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[9] * A[21]
        movq	rax, [%rcx+168]
        mulq	[%rcx+72]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[10] * A[20]
        movq	rax, [%rcx+160]
        mulq	[%rcx+80]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[11] * A[19]
        movq	rax, [%rcx+152]
        mulq	[%rcx+88]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[12] * A[18]
        movq	rax, [%rcx+144]
        mulq	[%rcx+96]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[13] * A[17]
        movq	rax, [%rcx+136]
        mulq	[%rcx+104]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[14] * A[16]
        movq	rax, [%rcx+128]
        mulq	[%rcx+112]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[15] * A[15]
        movq	rax, [%rcx+120]
        mulq	rax
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r9, r12
        adcq	r10, r13
        adcq	r11, r14
        movq	[%r8+240], r9
        ; A[8] * A[23]
        movq	rax, [%rcx+184]
        mulq	[%rcx+64]
        xorq	r9, r9
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[9] * A[22]
        movq	rax, [%rcx+176]
        mulq	[%rcx+72]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[10] * A[21]
        movq	rax, [%rcx+168]
        mulq	[%rcx+80]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[11] * A[20]
        movq	rax, [%rcx+160]
        mulq	[%rcx+88]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[12] * A[19]
        movq	rax, [%rcx+152]
        mulq	[%rcx+96]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[13] * A[18]
        movq	rax, [%rcx+144]
        mulq	[%rcx+104]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[14] * A[17]
        movq	rax, [%rcx+136]
        mulq	[%rcx+112]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[15] * A[16]
        movq	rax, [%rcx+128]
        mulq	[%rcx+120]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r10, r12
        adcq	r11, r13
        adcq	r9, r14
        movq	[%r8+248], r10
        ; A[9] * A[23]
        movq	rax, [%rcx+184]
        mulq	[%rcx+72]
        xorq	r10, r10
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[10] * A[22]
        movq	rax, [%rcx+176]
        mulq	[%rcx+80]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[11] * A[21]
        movq	rax, [%rcx+168]
        mulq	[%rcx+88]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[12] * A[20]
        movq	rax, [%rcx+160]
        mulq	[%rcx+96]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[13] * A[19]
        movq	rax, [%rcx+152]
        mulq	[%rcx+104]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[14] * A[18]
        movq	rax, [%rcx+144]
        mulq	[%rcx+112]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[15] * A[17]
        movq	rax, [%rcx+136]
        mulq	[%rcx+120]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[16] * A[16]
        movq	rax, [%rcx+128]
        mulq	rax
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r11, r12
        adcq	r9, r13
        adcq	r10, r14
        movq	[%r8+256], r11
        ; A[10] * A[23]
        movq	rax, [%rcx+184]
        mulq	[%rcx+80]
        xorq	r11, r11
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[11] * A[22]
        movq	rax, [%rcx+176]
        mulq	[%rcx+88]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[12] * A[21]
        movq	rax, [%rcx+168]
        mulq	[%rcx+96]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[13] * A[20]
        movq	rax, [%rcx+160]
        mulq	[%rcx+104]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[14] * A[19]
        movq	rax, [%rcx+152]
        mulq	[%rcx+112]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[15] * A[18]
        movq	rax, [%rcx+144]
        mulq	[%rcx+120]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[16] * A[17]
        movq	rax, [%rcx+136]
        mulq	[%rcx+128]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r9, r12
        adcq	r10, r13
        adcq	r11, r14
        movq	[%r8+264], r9
        ; A[11] * A[23]
        movq	rax, [%rcx+184]
        mulq	[%rcx+88]
        xorq	r9, r9
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[12] * A[22]
        movq	rax, [%rcx+176]
        mulq	[%rcx+96]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[13] * A[21]
        movq	rax, [%rcx+168]
        mulq	[%rcx+104]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[14] * A[20]
        movq	rax, [%rcx+160]
        mulq	[%rcx+112]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[15] * A[19]
        movq	rax, [%rcx+152]
        mulq	[%rcx+120]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[16] * A[18]
        movq	rax, [%rcx+144]
        mulq	[%rcx+128]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[17] * A[17]
        movq	rax, [%rcx+136]
        mulq	rax
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r10, r12
        adcq	r11, r13
        adcq	r9, r14
        movq	[%r8+272], r10
        ; A[12] * A[23]
        movq	rax, [%rcx+184]
        mulq	[%rcx+96]
        xorq	r10, r10
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[13] * A[22]
        movq	rax, [%rcx+176]
        mulq	[%rcx+104]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[14] * A[21]
        movq	rax, [%rcx+168]
        mulq	[%rcx+112]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[15] * A[20]
        movq	rax, [%rcx+160]
        mulq	[%rcx+120]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[16] * A[19]
        movq	rax, [%rcx+152]
        mulq	[%rcx+128]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[17] * A[18]
        movq	rax, [%rcx+144]
        mulq	[%rcx+136]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r11, r12
        adcq	r9, r13
        adcq	r10, r14
        movq	[%r8+280], r11
        ; A[13] * A[23]
        movq	rax, [%rcx+184]
        mulq	[%rcx+104]
        xorq	r11, r11
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[14] * A[22]
        movq	rax, [%rcx+176]
        mulq	[%rcx+112]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[15] * A[21]
        movq	rax, [%rcx+168]
        mulq	[%rcx+120]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[16] * A[20]
        movq	rax, [%rcx+160]
        mulq	[%rcx+128]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[17] * A[19]
        movq	rax, [%rcx+152]
        mulq	[%rcx+136]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[18] * A[18]
        movq	rax, [%rcx+144]
        mulq	rax
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r9, r12
        adcq	r10, r13
        adcq	r11, r14
        movq	[%r8+288], r9
        ; A[14] * A[23]
        movq	rax, [%rcx+184]
        mulq	[%rcx+112]
        xorq	r9, r9
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[15] * A[22]
        movq	rax, [%rcx+176]
        mulq	[%rcx+120]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[16] * A[21]
        movq	rax, [%rcx+168]
        mulq	[%rcx+128]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[17] * A[20]
        movq	rax, [%rcx+160]
        mulq	[%rcx+136]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[18] * A[19]
        movq	rax, [%rcx+152]
        mulq	[%rcx+144]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r10, r12
        adcq	r11, r13
        adcq	r9, r14
        movq	[%r8+296], r10
        ; A[15] * A[23]
        movq	rax, [%rcx+184]
        mulq	[%rcx+120]
        xorq	r10, r10
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[16] * A[22]
        movq	rax, [%rcx+176]
        mulq	[%rcx+128]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[17] * A[21]
        movq	rax, [%rcx+168]
        mulq	[%rcx+136]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[18] * A[20]
        movq	rax, [%rcx+160]
        mulq	[%rcx+144]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[19] * A[19]
        movq	rax, [%rcx+152]
        mulq	rax
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r11, r12
        adcq	r9, r13
        adcq	r10, r14
        movq	[%r8+304], r11
        ; A[16] * A[23]
        movq	rax, [%rcx+184]
        mulq	[%rcx+128]
        xorq	r11, r11
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[17] * A[22]
        movq	rax, [%rcx+176]
        mulq	[%rcx+136]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[18] * A[21]
        movq	rax, [%rcx+168]
        mulq	[%rcx+144]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[19] * A[20]
        movq	rax, [%rcx+160]
        mulq	[%rcx+152]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r9, r12
        adcq	r10, r13
        adcq	r11, r14
        movq	[%r8+312], r9
        ; A[17] * A[23]
        movq	rax, [%rcx+184]
        mulq	[%rcx+136]
        xorq	r9, r9
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[18] * A[22]
        movq	rax, [%rcx+176]
        mulq	[%rcx+144]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[19] * A[21]
        movq	rax, [%rcx+168]
        mulq	[%rcx+152]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[20] * A[20]
        movq	rax, [%rcx+160]
        mulq	rax
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r10, r12
        adcq	r11, r13
        adcq	r9, r14
        movq	[%r8+320], r10
        ; A[18] * A[23]
        movq	rax, [%rcx+184]
        mulq	[%rcx+144]
        xorq	r10, r10
        xorq	r14, r14
        movq	r12, rax
        movq	r13, rdx
        ; A[19] * A[22]
        movq	rax, [%rcx+176]
        mulq	[%rcx+152]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ; A[20] * A[21]
        movq	rax, [%rcx+168]
        mulq	[%rcx+160]
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        addq	r11, r12
        adcq	r9, r13
        adcq	r10, r14
        movq	[%r8+328], r11
        ; A[19] * A[23]
        movq	rax, [%rcx+184]
        mulq	[%rcx+152]
        xorq	r11, r11
        addq	r9, rax
        adcq	r10, rdx
        adcq	r11, 0
        addq	r9, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[20] * A[22]
        movq	rax, [%rcx+176]
        mulq	[%rcx+160]
        addq	r9, rax
        adcq	r10, rdx
        adcq	r11, 0
        addq	r9, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[21] * A[21]
        movq	rax, [%rcx+168]
        mulq	rax
        addq	r9, rax
        adcq	r10, rdx
        adcq	r11, 0
        movq	[%r8+336], r9
        ; A[20] * A[23]
        movq	rax, [%rcx+184]
        mulq	[%rcx+160]
        xorq	r9, r9
        addq	r10, rax
        adcq	r11, rdx
        adcq	r9, 0
        addq	r10, rax
        adcq	r11, rdx
        adcq	r9, 0
        ; A[21] * A[22]
        movq	rax, [%rcx+176]
        mulq	[%rcx+168]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r9, 0
        addq	r10, rax
        adcq	r11, rdx
        adcq	r9, 0
        movq	[%r8+344], r10
        ; A[21] * A[23]
        movq	rax, [%rcx+184]
        mulq	[%rcx+168]
        xorq	r10, r10
        addq	r11, rax
        adcq	r9, rdx
        adcq	r10, 0
        addq	r11, rax
        adcq	r9, rdx
        adcq	r10, 0
        ; A[22] * A[22]
        movq	rax, [%rcx+176]
        mulq	rax
        addq	r11, rax
        adcq	r9, rdx
        adcq	r10, 0
        movq	[%r8+352], r11
        ; A[22] * A[23]
        movq	rax, [%rcx+184]
        mulq	[%rcx+176]
        xorq	r11, r11
        addq	r9, rax
        adcq	r10, rdx
        adcq	r11, 0
        addq	r9, rax
        adcq	r10, rdx
        adcq	r11, 0
        movq	[%r8+360], r9
        ; A[23] * A[23]
        movq	rax, [%rcx+184]
        mulq	rax
        addq	r10, rax
        adcq	r11, rdx
        movq	[%r8+368], r10
        movq	[%r8+376], r11
        movq	rax, [%rsp]
        movq	rdx, [%rsp+8]
        movq	r12, [%rsp+16]
        movq	r13, [%rsp+24]
        movq	[%r8], rax
        movq	[%r8+8], rdx
        movq	[%r8+16], r12
        movq	[%r8+24], r13
        movq	rax, [%rsp+32]
        movq	rdx, [%rsp+40]
        movq	r12, [%rsp+48]
        movq	r13, [%rsp+56]
        movq	[%r8+32], rax
        movq	[%r8+40], rdx
        movq	[%r8+48], r12
        movq	[%r8+56], r13
        movq	rax, [%rsp+64]
        movq	rdx, [%rsp+72]
        movq	r12, [%rsp+80]
        movq	r13, [%rsp+88]
        movq	[%r8+64], rax
        movq	[%r8+72], rdx
        movq	[%r8+80], r12
        movq	[%r8+88], r13
        movq	rax, [%rsp+96]
        movq	rdx, [%rsp+104]
        movq	r12, [%rsp+112]
        movq	r13, [%rsp+120]
        movq	[%r8+96], rax
        movq	[%r8+104], rdx
        movq	[%r8+112], r12
        movq	[%r8+120], r13
        movq	rax, [%rsp+128]
        movq	rdx, [%rsp+136]
        movq	r12, [%rsp+144]
        movq	r13, [%rsp+152]
        movq	[%r8+128], rax
        movq	[%r8+136], rdx
        movq	[%r8+144], r12
        movq	[%r8+152], r13
        movq	rax, [%rsp+160]
        movq	rdx, [%rsp+168]
        movq	r12, [%rsp+176]
        movq	r13, [%rsp+184]
        movq	[%r8+160], rax
        movq	[%r8+168], rdx
        movq	[%r8+176], r12
        movq	[%r8+184], r13
        addq	rsp, 192
        pop	r14
        pop	r13
        pop	r12
        repz retq
sp_3072_sqr_24 ENDP
IFDEF HAVE_INTEL_AVX2
; /* Multiply a and b into r. (r = a * b)
;  *
;  * r   Result of multiplication.
;  * a   First number to multiply.
;  * b   Second number to multiply.
;  */
sp_3072_mul_avx2_24 PROC
        movq	rbp, r8
        movq	rax, rdx
        push	rbp
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        subq	rsp, 192
        movq	rdi, 0
        movq	rdx, [%rax]
        ; A[0] * B[0]
        mulx	r11, r10, [%rbp]
        ; A[0] * B[1]
        mulx	r12, r8, [%rbp+8]
        movq	[%rsp], r10
        adcxq	r11, r8
        ; A[0] * B[2]
        mulx	r13, r8, [%rbp+16]
        movq	[%rsp+8], r11
        adcxq	r12, r8
        ; A[0] * B[3]
        mulx	r14, r8, [%rbp+24]
        movq	[%rsp+16], r12
        adcxq	r13, r8
        movq	[%rsp+24], r13
        ; A[0] * B[4]
        mulx	r10, r8, [%rbp+32]
        adcxq	r14, r8
        ; A[0] * B[5]
        mulx	r11, r8, [%rbp+40]
        movq	[%rsp+32], r14
        adcxq	r10, r8
        ; A[0] * B[6]
        mulx	r12, r8, [%rbp+48]
        movq	[%rsp+40], r10
        adcxq	r11, r8
        ; A[0] * B[7]
        mulx	r13, r8, [%rbp+56]
        movq	[%rsp+48], r11
        adcxq	r12, r8
        movq	[%rsp+56], r12
        ; A[0] * B[8]
        mulx	r14, r8, [%rbp+64]
        adcxq	r13, r8
        ; A[0] * B[9]
        mulx	r10, r8, [%rbp+72]
        movq	[%rsp+64], r13
        adcxq	r14, r8
        ; A[0] * B[10]
        mulx	r11, r8, [%rbp+80]
        movq	[%rsp+72], r14
        adcxq	r10, r8
        ; A[0] * B[11]
        mulx	r12, r8, [%rbp+88]
        movq	[%rsp+80], r10
        adcxq	r11, r8
        movq	[%rsp+88], r11
        ; A[0] * B[12]
        mulx	r13, r8, [%rbp+96]
        adcxq	r12, r8
        ; A[0] * B[13]
        mulx	r14, r8, [%rbp+104]
        movq	[%rsp+96], r12
        adcxq	r13, r8
        ; A[0] * B[14]
        mulx	r10, r8, [%rbp+112]
        movq	[%rsp+104], r13
        adcxq	r14, r8
        ; A[0] * B[15]
        mulx	r11, r8, [%rbp+120]
        movq	[%rsp+112], r14
        adcxq	r10, r8
        movq	[%rsp+120], r10
        ; A[0] * B[16]
        mulx	r12, r8, [%rbp+128]
        adcxq	r11, r8
        ; A[0] * B[17]
        mulx	r13, r8, [%rbp+136]
        movq	[%rsp+128], r11
        adcxq	r12, r8
        ; A[0] * B[18]
        mulx	r14, r8, [%rbp+144]
        movq	[%rsp+136], r12
        adcxq	r13, r8
        ; A[0] * B[19]
        mulx	r10, r8, [%rbp+152]
        movq	[%rsp+144], r13
        adcxq	r14, r8
        movq	[%rsp+152], r14
        ; A[0] * B[20]
        mulx	r11, r8, [%rbp+160]
        adcxq	r10, r8
        ; A[0] * B[21]
        mulx	r12, r8, [%rbp+168]
        movq	[%rsp+160], r10
        adcxq	r11, r8
        ; A[0] * B[22]
        mulx	r13, r8, [%rbp+176]
        movq	[%rsp+168], r11
        adcxq	r12, r8
        ; A[0] * B[23]
        mulx	r14, r8, [%rbp+184]
        movq	rsi, r12
        adcxq	r13, r8
        adcxq	r14, rdi
        movq	r15, rdi
        adcxq	r15, rdi
        movq	rbx, r13
        movq	[%rcx+192], r14
        movq	rdx, [%rax+8]
        movq	r11, [%rsp+8]
        movq	r12, [%rsp+16]
        movq	r13, [%rsp+24]
        movq	r14, [%rsp+32]
        movq	r10, [%rsp+40]
        ; A[1] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[1] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	[%rsp+8], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[1] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	[%rsp+16], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[1] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	[%rsp+24], r13
        adcxq	r14, r8
        adoxq	r10, r9
        movq	[%rsp+32], r14
        movq	r11, [%rsp+48]
        movq	r12, [%rsp+56]
        movq	r13, [%rsp+64]
        movq	r14, [%rsp+72]
        ; A[1] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[1] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	[%rsp+40], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[1] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	[%rsp+48], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[1] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	[%rsp+56], r12
        adcxq	r13, r8
        adoxq	r14, r9
        movq	[%rsp+64], r13
        movq	r10, [%rsp+80]
        movq	r11, [%rsp+88]
        movq	r12, [%rsp+96]
        movq	r13, [%rsp+104]
        ; A[1] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[1] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	[%rsp+72], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[1] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	[%rsp+80], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[1] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	[%rsp+88], r11
        adcxq	r12, r8
        adoxq	r13, r9
        movq	[%rsp+96], r12
        movq	r14, [%rsp+112]
        movq	r10, [%rsp+120]
        movq	r11, [%rsp+128]
        movq	r12, [%rsp+136]
        ; A[1] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[1] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	[%rsp+104], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[1] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	[%rsp+112], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[1] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	[%rsp+120], r10
        adcxq	r11, r8
        adoxq	r12, r9
        movq	[%rsp+128], r11
        movq	r13, [%rsp+144]
        movq	r14, [%rsp+152]
        movq	r10, [%rsp+160]
        movq	r11, [%rsp+168]
        ; A[1] * B[16]
        mulx	r9, r8, [%rbp+128]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[1] * B[17]
        mulx	r9, r8, [%rbp+136]
        movq	[%rsp+136], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[1] * B[18]
        mulx	r9, r8, [%rbp+144]
        movq	[%rsp+144], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[1] * B[19]
        mulx	r9, r8, [%rbp+152]
        movq	[%rsp+152], r14
        adcxq	r10, r8
        adoxq	r11, r9
        movq	[%rsp+160], r10
        movq	r12, rsi
        movq	r13, rbx
        movq	r14, [%rcx+192]
        ; A[1] * B[20]
        mulx	r9, r8, [%rbp+160]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[1] * B[21]
        mulx	r9, r8, [%rbp+168]
        movq	[%rsp+168], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[1] * B[22]
        mulx	r9, r8, [%rbp+176]
        movq	rsi, r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[1] * B[23]
        mulx	r9, r8, [%rbp+184]
        movq	rbx, r13
        movq	r10, rdi
        adcxq	r14, r8
        adoxq	r10, r9
        adcxq	r10, r15
        movq	r15, rdi
        adoxq	r15, rdi
        adcxq	r15, rdi
        movq	[%rcx+192], r14
        movq	[%rcx+200], r10
        movq	rdx, [%rax+16]
        movq	r12, [%rsp+16]
        movq	r13, [%rsp+24]
        movq	r14, [%rsp+32]
        movq	r10, [%rsp+40]
        movq	r11, [%rsp+48]
        ; A[2] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[2] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	[%rsp+16], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[2] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	[%rsp+24], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[2] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	[%rsp+32], r14
        adcxq	r10, r8
        adoxq	r11, r9
        movq	[%rsp+40], r10
        movq	r12, [%rsp+56]
        movq	r13, [%rsp+64]
        movq	r14, [%rsp+72]
        movq	r10, [%rsp+80]
        ; A[2] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[2] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	[%rsp+48], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[2] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	[%rsp+56], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[2] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	[%rsp+64], r13
        adcxq	r14, r8
        adoxq	r10, r9
        movq	[%rsp+72], r14
        movq	r11, [%rsp+88]
        movq	r12, [%rsp+96]
        movq	r13, [%rsp+104]
        movq	r14, [%rsp+112]
        ; A[2] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[2] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	[%rsp+80], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[2] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	[%rsp+88], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[2] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	[%rsp+96], r12
        adcxq	r13, r8
        adoxq	r14, r9
        movq	[%rsp+104], r13
        movq	r10, [%rsp+120]
        movq	r11, [%rsp+128]
        movq	r12, [%rsp+136]
        movq	r13, [%rsp+144]
        ; A[2] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[2] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	[%rsp+112], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[2] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	[%rsp+120], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[2] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	[%rsp+128], r11
        adcxq	r12, r8
        adoxq	r13, r9
        movq	[%rsp+136], r12
        movq	r14, [%rsp+152]
        movq	r10, [%rsp+160]
        movq	r11, [%rsp+168]
        movq	r12, rsi
        ; A[2] * B[16]
        mulx	r9, r8, [%rbp+128]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[2] * B[17]
        mulx	r9, r8, [%rbp+136]
        movq	[%rsp+144], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[2] * B[18]
        mulx	r9, r8, [%rbp+144]
        movq	[%rsp+152], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[2] * B[19]
        mulx	r9, r8, [%rbp+152]
        movq	[%rsp+160], r10
        adcxq	r11, r8
        adoxq	r12, r9
        movq	[%rsp+168], r11
        movq	r13, rbx
        movq	r14, [%rcx+192]
        movq	r10, [%rcx+200]
        ; A[2] * B[20]
        mulx	r9, r8, [%rbp+160]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[2] * B[21]
        mulx	r9, r8, [%rbp+168]
        movq	rsi, r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[2] * B[22]
        mulx	r9, r8, [%rbp+176]
        movq	rbx, r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[2] * B[23]
        mulx	r9, r8, [%rbp+184]
        movq	[%rcx+192], r14
        movq	r11, rdi
        adcxq	r10, r8
        adoxq	r11, r9
        adcxq	r11, r15
        movq	r15, rdi
        adoxq	r15, rdi
        adcxq	r15, rdi
        movq	[%rcx+200], r10
        movq	[%rcx+208], r11
        movq	rdx, [%rax+24]
        movq	r13, [%rsp+24]
        movq	r14, [%rsp+32]
        movq	r10, [%rsp+40]
        movq	r11, [%rsp+48]
        movq	r12, [%rsp+56]
        ; A[3] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[3] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	[%rsp+24], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[3] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	[%rsp+32], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[3] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	[%rsp+40], r10
        adcxq	r11, r8
        adoxq	r12, r9
        movq	[%rsp+48], r11
        movq	r13, [%rsp+64]
        movq	r14, [%rsp+72]
        movq	r10, [%rsp+80]
        movq	r11, [%rsp+88]
        ; A[3] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[3] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	[%rsp+56], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[3] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	[%rsp+64], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[3] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	[%rsp+72], r14
        adcxq	r10, r8
        adoxq	r11, r9
        movq	[%rsp+80], r10
        movq	r12, [%rsp+96]
        movq	r13, [%rsp+104]
        movq	r14, [%rsp+112]
        movq	r10, [%rsp+120]
        ; A[3] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[3] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	[%rsp+88], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[3] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	[%rsp+96], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[3] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	[%rsp+104], r13
        adcxq	r14, r8
        adoxq	r10, r9
        movq	[%rsp+112], r14
        movq	r11, [%rsp+128]
        movq	r12, [%rsp+136]
        movq	r13, [%rsp+144]
        movq	r14, [%rsp+152]
        ; A[3] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[3] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	[%rsp+120], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[3] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	[%rsp+128], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[3] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	[%rsp+136], r12
        adcxq	r13, r8
        adoxq	r14, r9
        movq	[%rsp+144], r13
        movq	r10, [%rsp+160]
        movq	r11, [%rsp+168]
        movq	r12, rsi
        movq	r13, rbx
        ; A[3] * B[16]
        mulx	r9, r8, [%rbp+128]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[3] * B[17]
        mulx	r9, r8, [%rbp+136]
        movq	[%rsp+152], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[3] * B[18]
        mulx	r9, r8, [%rbp+144]
        movq	[%rsp+160], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[3] * B[19]
        mulx	r9, r8, [%rbp+152]
        movq	[%rsp+168], r11
        adcxq	r12, r8
        adoxq	r13, r9
        movq	rsi, r12
        movq	r14, [%rcx+192]
        movq	r10, [%rcx+200]
        movq	r11, [%rcx+208]
        ; A[3] * B[20]
        mulx	r9, r8, [%rbp+160]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[3] * B[21]
        mulx	r9, r8, [%rbp+168]
        movq	rbx, r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[3] * B[22]
        mulx	r9, r8, [%rbp+176]
        movq	[%rcx+192], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[3] * B[23]
        mulx	r9, r8, [%rbp+184]
        movq	[%rcx+200], r10
        movq	r12, rdi
        adcxq	r11, r8
        adoxq	r12, r9
        adcxq	r12, r15
        movq	r15, rdi
        adoxq	r15, rdi
        adcxq	r15, rdi
        movq	[%rcx+208], r11
        movq	[%rcx+216], r12
        movq	rdx, [%rax+32]
        movq	r14, [%rsp+32]
        movq	r10, [%rsp+40]
        movq	r11, [%rsp+48]
        movq	r12, [%rsp+56]
        movq	r13, [%rsp+64]
        ; A[4] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[4] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	[%rsp+32], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[4] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	[%rsp+40], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[4] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	[%rsp+48], r11
        adcxq	r12, r8
        adoxq	r13, r9
        movq	[%rsp+56], r12
        movq	r14, [%rsp+72]
        movq	r10, [%rsp+80]
        movq	r11, [%rsp+88]
        movq	r12, [%rsp+96]
        ; A[4] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[4] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	[%rsp+64], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[4] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	[%rsp+72], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[4] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	[%rsp+80], r10
        adcxq	r11, r8
        adoxq	r12, r9
        movq	[%rsp+88], r11
        movq	r13, [%rsp+104]
        movq	r14, [%rsp+112]
        movq	r10, [%rsp+120]
        movq	r11, [%rsp+128]
        ; A[4] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[4] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	[%rsp+96], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[4] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	[%rsp+104], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[4] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	[%rsp+112], r14
        adcxq	r10, r8
        adoxq	r11, r9
        movq	[%rsp+120], r10
        movq	r12, [%rsp+136]
        movq	r13, [%rsp+144]
        movq	r14, [%rsp+152]
        movq	r10, [%rsp+160]
        ; A[4] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[4] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	[%rsp+128], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[4] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	[%rsp+136], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[4] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	[%rsp+144], r13
        adcxq	r14, r8
        adoxq	r10, r9
        movq	[%rsp+152], r14
        movq	r11, [%rsp+168]
        movq	r12, rsi
        movq	r13, rbx
        movq	r14, [%rcx+192]
        ; A[4] * B[16]
        mulx	r9, r8, [%rbp+128]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[4] * B[17]
        mulx	r9, r8, [%rbp+136]
        movq	[%rsp+160], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[4] * B[18]
        mulx	r9, r8, [%rbp+144]
        movq	[%rsp+168], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[4] * B[19]
        mulx	r9, r8, [%rbp+152]
        movq	rsi, r12
        adcxq	r13, r8
        adoxq	r14, r9
        movq	rbx, r13
        movq	r10, [%rcx+200]
        movq	r11, [%rcx+208]
        movq	r12, [%rcx+216]
        ; A[4] * B[20]
        mulx	r9, r8, [%rbp+160]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[4] * B[21]
        mulx	r9, r8, [%rbp+168]
        movq	[%rcx+192], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[4] * B[22]
        mulx	r9, r8, [%rbp+176]
        movq	[%rcx+200], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[4] * B[23]
        mulx	r9, r8, [%rbp+184]
        movq	[%rcx+208], r11
        movq	r13, rdi
        adcxq	r12, r8
        adoxq	r13, r9
        adcxq	r13, r15
        movq	r15, rdi
        adoxq	r15, rdi
        adcxq	r15, rdi
        movq	[%rcx+216], r12
        movq	[%rcx+224], r13
        movq	rdx, [%rax+40]
        movq	r10, [%rsp+40]
        movq	r11, [%rsp+48]
        movq	r12, [%rsp+56]
        movq	r13, [%rsp+64]
        movq	r14, [%rsp+72]
        ; A[5] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[5] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	[%rsp+40], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[5] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	[%rsp+48], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[5] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	[%rsp+56], r12
        adcxq	r13, r8
        adoxq	r14, r9
        movq	[%rsp+64], r13
        movq	r10, [%rsp+80]
        movq	r11, [%rsp+88]
        movq	r12, [%rsp+96]
        movq	r13, [%rsp+104]
        ; A[5] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[5] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	[%rsp+72], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[5] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	[%rsp+80], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[5] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	[%rsp+88], r11
        adcxq	r12, r8
        adoxq	r13, r9
        movq	[%rsp+96], r12
        movq	r14, [%rsp+112]
        movq	r10, [%rsp+120]
        movq	r11, [%rsp+128]
        movq	r12, [%rsp+136]
        ; A[5] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[5] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	[%rsp+104], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[5] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	[%rsp+112], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[5] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	[%rsp+120], r10
        adcxq	r11, r8
        adoxq	r12, r9
        movq	[%rsp+128], r11
        movq	r13, [%rsp+144]
        movq	r14, [%rsp+152]
        movq	r10, [%rsp+160]
        movq	r11, [%rsp+168]
        ; A[5] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[5] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	[%rsp+136], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[5] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	[%rsp+144], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[5] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	[%rsp+152], r14
        adcxq	r10, r8
        adoxq	r11, r9
        movq	[%rsp+160], r10
        movq	r12, rsi
        movq	r13, rbx
        movq	r14, [%rcx+192]
        movq	r10, [%rcx+200]
        ; A[5] * B[16]
        mulx	r9, r8, [%rbp+128]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[5] * B[17]
        mulx	r9, r8, [%rbp+136]
        movq	[%rsp+168], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[5] * B[18]
        mulx	r9, r8, [%rbp+144]
        movq	rsi, r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[5] * B[19]
        mulx	r9, r8, [%rbp+152]
        movq	rbx, r13
        adcxq	r14, r8
        adoxq	r10, r9
        movq	[%rcx+192], r14
        movq	r11, [%rcx+208]
        movq	r12, [%rcx+216]
        movq	r13, [%rcx+224]
        ; A[5] * B[20]
        mulx	r9, r8, [%rbp+160]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[5] * B[21]
        mulx	r9, r8, [%rbp+168]
        movq	[%rcx+200], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[5] * B[22]
        mulx	r9, r8, [%rbp+176]
        movq	[%rcx+208], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[5] * B[23]
        mulx	r9, r8, [%rbp+184]
        movq	[%rcx+216], r12
        movq	r14, rdi
        adcxq	r13, r8
        adoxq	r14, r9
        adcxq	r14, r15
        movq	r15, rdi
        adoxq	r15, rdi
        adcxq	r15, rdi
        movq	[%rcx+224], r13
        movq	[%rcx+232], r14
        movq	rdx, [%rax+48]
        movq	r11, [%rsp+48]
        movq	r12, [%rsp+56]
        movq	r13, [%rsp+64]
        movq	r14, [%rsp+72]
        movq	r10, [%rsp+80]
        ; A[6] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[6] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	[%rsp+48], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[6] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	[%rsp+56], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[6] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	[%rsp+64], r13
        adcxq	r14, r8
        adoxq	r10, r9
        movq	[%rsp+72], r14
        movq	r11, [%rsp+88]
        movq	r12, [%rsp+96]
        movq	r13, [%rsp+104]
        movq	r14, [%rsp+112]
        ; A[6] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[6] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	[%rsp+80], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[6] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	[%rsp+88], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[6] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	[%rsp+96], r12
        adcxq	r13, r8
        adoxq	r14, r9
        movq	[%rsp+104], r13
        movq	r10, [%rsp+120]
        movq	r11, [%rsp+128]
        movq	r12, [%rsp+136]
        movq	r13, [%rsp+144]
        ; A[6] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[6] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	[%rsp+112], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[6] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	[%rsp+120], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[6] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	[%rsp+128], r11
        adcxq	r12, r8
        adoxq	r13, r9
        movq	[%rsp+136], r12
        movq	r14, [%rsp+152]
        movq	r10, [%rsp+160]
        movq	r11, [%rsp+168]
        movq	r12, rsi
        ; A[6] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[6] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	[%rsp+144], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[6] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	[%rsp+152], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[6] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	[%rsp+160], r10
        adcxq	r11, r8
        adoxq	r12, r9
        movq	[%rsp+168], r11
        movq	r13, rbx
        movq	r14, [%rcx+192]
        movq	r10, [%rcx+200]
        movq	r11, [%rcx+208]
        ; A[6] * B[16]
        mulx	r9, r8, [%rbp+128]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[6] * B[17]
        mulx	r9, r8, [%rbp+136]
        movq	rsi, r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[6] * B[18]
        mulx	r9, r8, [%rbp+144]
        movq	rbx, r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[6] * B[19]
        mulx	r9, r8, [%rbp+152]
        movq	[%rcx+192], r14
        adcxq	r10, r8
        adoxq	r11, r9
        movq	[%rcx+200], r10
        movq	r12, [%rcx+216]
        movq	r13, [%rcx+224]
        movq	r14, [%rcx+232]
        ; A[6] * B[20]
        mulx	r9, r8, [%rbp+160]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[6] * B[21]
        mulx	r9, r8, [%rbp+168]
        movq	[%rcx+208], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[6] * B[22]
        mulx	r9, r8, [%rbp+176]
        movq	[%rcx+216], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[6] * B[23]
        mulx	r9, r8, [%rbp+184]
        movq	[%rcx+224], r13
        movq	r10, rdi
        adcxq	r14, r8
        adoxq	r10, r9
        adcxq	r10, r15
        movq	r15, rdi
        adoxq	r15, rdi
        adcxq	r15, rdi
        movq	[%rcx+232], r14
        movq	[%rcx+240], r10
        movq	rdx, [%rax+56]
        movq	r12, [%rsp+56]
        movq	r13, [%rsp+64]
        movq	r14, [%rsp+72]
        movq	r10, [%rsp+80]
        movq	r11, [%rsp+88]
        ; A[7] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[7] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	[%rsp+56], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[7] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	[%rsp+64], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[7] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	[%rsp+72], r14
        adcxq	r10, r8
        adoxq	r11, r9
        movq	[%rsp+80], r10
        movq	r12, [%rsp+96]
        movq	r13, [%rsp+104]
        movq	r14, [%rsp+112]
        movq	r10, [%rsp+120]
        ; A[7] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[7] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	[%rsp+88], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[7] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	[%rsp+96], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[7] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	[%rsp+104], r13
        adcxq	r14, r8
        adoxq	r10, r9
        movq	[%rsp+112], r14
        movq	r11, [%rsp+128]
        movq	r12, [%rsp+136]
        movq	r13, [%rsp+144]
        movq	r14, [%rsp+152]
        ; A[7] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[7] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	[%rsp+120], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[7] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	[%rsp+128], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[7] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	[%rsp+136], r12
        adcxq	r13, r8
        adoxq	r14, r9
        movq	[%rsp+144], r13
        movq	r10, [%rsp+160]
        movq	r11, [%rsp+168]
        movq	r12, rsi
        movq	r13, rbx
        ; A[7] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[7] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	[%rsp+152], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[7] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	[%rsp+160], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[7] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	[%rsp+168], r11
        adcxq	r12, r8
        adoxq	r13, r9
        movq	rsi, r12
        movq	r14, [%rcx+192]
        movq	r10, [%rcx+200]
        movq	r11, [%rcx+208]
        movq	r12, [%rcx+216]
        ; A[7] * B[16]
        mulx	r9, r8, [%rbp+128]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[7] * B[17]
        mulx	r9, r8, [%rbp+136]
        movq	rbx, r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[7] * B[18]
        mulx	r9, r8, [%rbp+144]
        movq	[%rcx+192], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[7] * B[19]
        mulx	r9, r8, [%rbp+152]
        movq	[%rcx+200], r10
        adcxq	r11, r8
        adoxq	r12, r9
        movq	[%rcx+208], r11
        movq	r13, [%rcx+224]
        movq	r14, [%rcx+232]
        movq	r10, [%rcx+240]
        ; A[7] * B[20]
        mulx	r9, r8, [%rbp+160]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[7] * B[21]
        mulx	r9, r8, [%rbp+168]
        movq	[%rcx+216], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[7] * B[22]
        mulx	r9, r8, [%rbp+176]
        movq	[%rcx+224], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[7] * B[23]
        mulx	r9, r8, [%rbp+184]
        movq	[%rcx+232], r14
        movq	r11, rdi
        adcxq	r10, r8
        adoxq	r11, r9
        adcxq	r11, r15
        movq	r15, rdi
        adoxq	r15, rdi
        adcxq	r15, rdi
        movq	[%rcx+240], r10
        movq	[%rcx+248], r11
        movq	rdx, [%rax+64]
        movq	r13, [%rsp+64]
        movq	r14, [%rsp+72]
        movq	r10, [%rsp+80]
        movq	r11, [%rsp+88]
        movq	r12, [%rsp+96]
        ; A[8] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[8] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	[%rsp+64], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[8] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	[%rsp+72], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[8] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	[%rsp+80], r10
        adcxq	r11, r8
        adoxq	r12, r9
        movq	[%rsp+88], r11
        movq	r13, [%rsp+104]
        movq	r14, [%rsp+112]
        movq	r10, [%rsp+120]
        movq	r11, [%rsp+128]
        ; A[8] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[8] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	[%rsp+96], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[8] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	[%rsp+104], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[8] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	[%rsp+112], r14
        adcxq	r10, r8
        adoxq	r11, r9
        movq	[%rsp+120], r10
        movq	r12, [%rsp+136]
        movq	r13, [%rsp+144]
        movq	r14, [%rsp+152]
        movq	r10, [%rsp+160]
        ; A[8] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[8] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	[%rsp+128], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[8] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	[%rsp+136], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[8] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	[%rsp+144], r13
        adcxq	r14, r8
        adoxq	r10, r9
        movq	[%rsp+152], r14
        movq	r11, [%rsp+168]
        movq	r12, rsi
        movq	r13, rbx
        movq	r14, [%rcx+192]
        ; A[8] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[8] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	[%rsp+160], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[8] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	[%rsp+168], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[8] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	rsi, r12
        adcxq	r13, r8
        adoxq	r14, r9
        movq	rbx, r13
        movq	r10, [%rcx+200]
        movq	r11, [%rcx+208]
        movq	r12, [%rcx+216]
        movq	r13, [%rcx+224]
        ; A[8] * B[16]
        mulx	r9, r8, [%rbp+128]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[8] * B[17]
        mulx	r9, r8, [%rbp+136]
        movq	[%rcx+192], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[8] * B[18]
        mulx	r9, r8, [%rbp+144]
        movq	[%rcx+200], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[8] * B[19]
        mulx	r9, r8, [%rbp+152]
        movq	[%rcx+208], r11
        adcxq	r12, r8
        adoxq	r13, r9
        movq	[%rcx+216], r12
        movq	r14, [%rcx+232]
        movq	r10, [%rcx+240]
        movq	r11, [%rcx+248]
        ; A[8] * B[20]
        mulx	r9, r8, [%rbp+160]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[8] * B[21]
        mulx	r9, r8, [%rbp+168]
        movq	[%rcx+224], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[8] * B[22]
        mulx	r9, r8, [%rbp+176]
        movq	[%rcx+232], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[8] * B[23]
        mulx	r9, r8, [%rbp+184]
        movq	[%rcx+240], r10
        movq	r12, rdi
        adcxq	r11, r8
        adoxq	r12, r9
        adcxq	r12, r15
        movq	r15, rdi
        adoxq	r15, rdi
        adcxq	r15, rdi
        movq	[%rcx+248], r11
        movq	[%rcx+256], r12
        movq	rdx, [%rax+72]
        movq	r14, [%rsp+72]
        movq	r10, [%rsp+80]
        movq	r11, [%rsp+88]
        movq	r12, [%rsp+96]
        movq	r13, [%rsp+104]
        ; A[9] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[9] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	[%rsp+72], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[9] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	[%rsp+80], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[9] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	[%rsp+88], r11
        adcxq	r12, r8
        adoxq	r13, r9
        movq	[%rsp+96], r12
        movq	r14, [%rsp+112]
        movq	r10, [%rsp+120]
        movq	r11, [%rsp+128]
        movq	r12, [%rsp+136]
        ; A[9] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[9] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	[%rsp+104], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[9] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	[%rsp+112], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[9] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	[%rsp+120], r10
        adcxq	r11, r8
        adoxq	r12, r9
        movq	[%rsp+128], r11
        movq	r13, [%rsp+144]
        movq	r14, [%rsp+152]
        movq	r10, [%rsp+160]
        movq	r11, [%rsp+168]
        ; A[9] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[9] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	[%rsp+136], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[9] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	[%rsp+144], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[9] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	[%rsp+152], r14
        adcxq	r10, r8
        adoxq	r11, r9
        movq	[%rsp+160], r10
        movq	r12, rsi
        movq	r13, rbx
        movq	r14, [%rcx+192]
        movq	r10, [%rcx+200]
        ; A[9] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[9] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	[%rsp+168], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[9] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	rsi, r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[9] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	rbx, r13
        adcxq	r14, r8
        adoxq	r10, r9
        movq	[%rcx+192], r14
        movq	r11, [%rcx+208]
        movq	r12, [%rcx+216]
        movq	r13, [%rcx+224]
        movq	r14, [%rcx+232]
        ; A[9] * B[16]
        mulx	r9, r8, [%rbp+128]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[9] * B[17]
        mulx	r9, r8, [%rbp+136]
        movq	[%rcx+200], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[9] * B[18]
        mulx	r9, r8, [%rbp+144]
        movq	[%rcx+208], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[9] * B[19]
        mulx	r9, r8, [%rbp+152]
        movq	[%rcx+216], r12
        adcxq	r13, r8
        adoxq	r14, r9
        movq	[%rcx+224], r13
        movq	r10, [%rcx+240]
        movq	r11, [%rcx+248]
        movq	r12, [%rcx+256]
        ; A[9] * B[20]
        mulx	r9, r8, [%rbp+160]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[9] * B[21]
        mulx	r9, r8, [%rbp+168]
        movq	[%rcx+232], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[9] * B[22]
        mulx	r9, r8, [%rbp+176]
        movq	[%rcx+240], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[9] * B[23]
        mulx	r9, r8, [%rbp+184]
        movq	[%rcx+248], r11
        movq	r13, rdi
        adcxq	r12, r8
        adoxq	r13, r9
        adcxq	r13, r15
        movq	r15, rdi
        adoxq	r15, rdi
        adcxq	r15, rdi
        movq	[%rcx+256], r12
        movq	[%rcx+264], r13
        movq	rdx, [%rax+80]
        movq	r10, [%rsp+80]
        movq	r11, [%rsp+88]
        movq	r12, [%rsp+96]
        movq	r13, [%rsp+104]
        movq	r14, [%rsp+112]
        ; A[10] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[10] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	[%rsp+80], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[10] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	[%rsp+88], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[10] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	[%rsp+96], r12
        adcxq	r13, r8
        adoxq	r14, r9
        movq	[%rsp+104], r13
        movq	r10, [%rsp+120]
        movq	r11, [%rsp+128]
        movq	r12, [%rsp+136]
        movq	r13, [%rsp+144]
        ; A[10] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[10] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	[%rsp+112], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[10] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	[%rsp+120], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[10] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	[%rsp+128], r11
        adcxq	r12, r8
        adoxq	r13, r9
        movq	[%rsp+136], r12
        movq	r14, [%rsp+152]
        movq	r10, [%rsp+160]
        movq	r11, [%rsp+168]
        movq	r12, rsi
        ; A[10] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[10] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	[%rsp+144], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[10] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	[%rsp+152], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[10] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	[%rsp+160], r10
        adcxq	r11, r8
        adoxq	r12, r9
        movq	[%rsp+168], r11
        movq	r13, rbx
        movq	r14, [%rcx+192]
        movq	r10, [%rcx+200]
        movq	r11, [%rcx+208]
        ; A[10] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[10] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	rsi, r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[10] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	rbx, r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[10] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	[%rcx+192], r14
        adcxq	r10, r8
        adoxq	r11, r9
        movq	[%rcx+200], r10
        movq	r12, [%rcx+216]
        movq	r13, [%rcx+224]
        movq	r14, [%rcx+232]
        movq	r10, [%rcx+240]
        ; A[10] * B[16]
        mulx	r9, r8, [%rbp+128]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[10] * B[17]
        mulx	r9, r8, [%rbp+136]
        movq	[%rcx+208], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[10] * B[18]
        mulx	r9, r8, [%rbp+144]
        movq	[%rcx+216], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[10] * B[19]
        mulx	r9, r8, [%rbp+152]
        movq	[%rcx+224], r13
        adcxq	r14, r8
        adoxq	r10, r9
        movq	[%rcx+232], r14
        movq	r11, [%rcx+248]
        movq	r12, [%rcx+256]
        movq	r13, [%rcx+264]
        ; A[10] * B[20]
        mulx	r9, r8, [%rbp+160]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[10] * B[21]
        mulx	r9, r8, [%rbp+168]
        movq	[%rcx+240], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[10] * B[22]
        mulx	r9, r8, [%rbp+176]
        movq	[%rcx+248], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[10] * B[23]
        mulx	r9, r8, [%rbp+184]
        movq	[%rcx+256], r12
        movq	r14, rdi
        adcxq	r13, r8
        adoxq	r14, r9
        adcxq	r14, r15
        movq	r15, rdi
        adoxq	r15, rdi
        adcxq	r15, rdi
        movq	[%rcx+264], r13
        movq	[%rcx+272], r14
        movq	rdx, [%rax+88]
        movq	r11, [%rsp+88]
        movq	r12, [%rsp+96]
        movq	r13, [%rsp+104]
        movq	r14, [%rsp+112]
        movq	r10, [%rsp+120]
        ; A[11] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[11] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	[%rsp+88], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[11] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	[%rsp+96], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[11] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	[%rsp+104], r13
        adcxq	r14, r8
        adoxq	r10, r9
        movq	[%rsp+112], r14
        movq	r11, [%rsp+128]
        movq	r12, [%rsp+136]
        movq	r13, [%rsp+144]
        movq	r14, [%rsp+152]
        ; A[11] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[11] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	[%rsp+120], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[11] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	[%rsp+128], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[11] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	[%rsp+136], r12
        adcxq	r13, r8
        adoxq	r14, r9
        movq	[%rsp+144], r13
        movq	r10, [%rsp+160]
        movq	r11, [%rsp+168]
        movq	r12, rsi
        movq	r13, rbx
        ; A[11] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[11] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	[%rsp+152], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[11] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	[%rsp+160], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[11] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	[%rsp+168], r11
        adcxq	r12, r8
        adoxq	r13, r9
        movq	rsi, r12
        movq	r14, [%rcx+192]
        movq	r10, [%rcx+200]
        movq	r11, [%rcx+208]
        movq	r12, [%rcx+216]
        ; A[11] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[11] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	rbx, r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[11] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	[%rcx+192], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[11] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	[%rcx+200], r10
        adcxq	r11, r8
        adoxq	r12, r9
        movq	[%rcx+208], r11
        movq	r13, [%rcx+224]
        movq	r14, [%rcx+232]
        movq	r10, [%rcx+240]
        movq	r11, [%rcx+248]
        ; A[11] * B[16]
        mulx	r9, r8, [%rbp+128]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[11] * B[17]
        mulx	r9, r8, [%rbp+136]
        movq	[%rcx+216], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[11] * B[18]
        mulx	r9, r8, [%rbp+144]
        movq	[%rcx+224], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[11] * B[19]
        mulx	r9, r8, [%rbp+152]
        movq	[%rcx+232], r14
        adcxq	r10, r8
        adoxq	r11, r9
        movq	[%rcx+240], r10
        movq	r12, [%rcx+256]
        movq	r13, [%rcx+264]
        movq	r14, [%rcx+272]
        ; A[11] * B[20]
        mulx	r9, r8, [%rbp+160]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[11] * B[21]
        mulx	r9, r8, [%rbp+168]
        movq	[%rcx+248], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[11] * B[22]
        mulx	r9, r8, [%rbp+176]
        movq	[%rcx+256], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[11] * B[23]
        mulx	r9, r8, [%rbp+184]
        movq	[%rcx+264], r13
        movq	r10, rdi
        adcxq	r14, r8
        adoxq	r10, r9
        adcxq	r10, r15
        movq	r15, rdi
        adoxq	r15, rdi
        adcxq	r15, rdi
        movq	[%rcx+272], r14
        movq	[%rcx+280], r10
        movq	rdx, [%rax+96]
        movq	r12, [%rsp+96]
        movq	r13, [%rsp+104]
        movq	r14, [%rsp+112]
        movq	r10, [%rsp+120]
        movq	r11, [%rsp+128]
        ; A[12] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[12] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	[%rsp+96], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[12] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	[%rsp+104], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[12] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	[%rsp+112], r14
        adcxq	r10, r8
        adoxq	r11, r9
        movq	[%rsp+120], r10
        movq	r12, [%rsp+136]
        movq	r13, [%rsp+144]
        movq	r14, [%rsp+152]
        movq	r10, [%rsp+160]
        ; A[12] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[12] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	[%rsp+128], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[12] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	[%rsp+136], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[12] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	[%rsp+144], r13
        adcxq	r14, r8
        adoxq	r10, r9
        movq	[%rsp+152], r14
        movq	r11, [%rsp+168]
        movq	r12, rsi
        movq	r13, rbx
        movq	r14, [%rcx+192]
        ; A[12] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[12] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	[%rsp+160], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[12] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	[%rsp+168], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[12] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	rsi, r12
        adcxq	r13, r8
        adoxq	r14, r9
        movq	rbx, r13
        movq	r10, [%rcx+200]
        movq	r11, [%rcx+208]
        movq	r12, [%rcx+216]
        movq	r13, [%rcx+224]
        ; A[12] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[12] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	[%rcx+192], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[12] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	[%rcx+200], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[12] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	[%rcx+208], r11
        adcxq	r12, r8
        adoxq	r13, r9
        movq	[%rcx+216], r12
        movq	r14, [%rcx+232]
        movq	r10, [%rcx+240]
        movq	r11, [%rcx+248]
        movq	r12, [%rcx+256]
        ; A[12] * B[16]
        mulx	r9, r8, [%rbp+128]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[12] * B[17]
        mulx	r9, r8, [%rbp+136]
        movq	[%rcx+224], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[12] * B[18]
        mulx	r9, r8, [%rbp+144]
        movq	[%rcx+232], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[12] * B[19]
        mulx	r9, r8, [%rbp+152]
        movq	[%rcx+240], r10
        adcxq	r11, r8
        adoxq	r12, r9
        movq	[%rcx+248], r11
        movq	r13, [%rcx+264]
        movq	r14, [%rcx+272]
        movq	r10, [%rcx+280]
        ; A[12] * B[20]
        mulx	r9, r8, [%rbp+160]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[12] * B[21]
        mulx	r9, r8, [%rbp+168]
        movq	[%rcx+256], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[12] * B[22]
        mulx	r9, r8, [%rbp+176]
        movq	[%rcx+264], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[12] * B[23]
        mulx	r9, r8, [%rbp+184]
        movq	[%rcx+272], r14
        movq	r11, rdi
        adcxq	r10, r8
        adoxq	r11, r9
        adcxq	r11, r15
        movq	r15, rdi
        adoxq	r15, rdi
        adcxq	r15, rdi
        movq	[%rcx+280], r10
        movq	[%rcx+288], r11
        movq	rdx, [%rax+104]
        movq	r13, [%rsp+104]
        movq	r14, [%rsp+112]
        movq	r10, [%rsp+120]
        movq	r11, [%rsp+128]
        movq	r12, [%rsp+136]
        ; A[13] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[13] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	[%rsp+104], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[13] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	[%rsp+112], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[13] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	[%rsp+120], r10
        adcxq	r11, r8
        adoxq	r12, r9
        movq	[%rsp+128], r11
        movq	r13, [%rsp+144]
        movq	r14, [%rsp+152]
        movq	r10, [%rsp+160]
        movq	r11, [%rsp+168]
        ; A[13] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[13] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	[%rsp+136], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[13] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	[%rsp+144], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[13] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	[%rsp+152], r14
        adcxq	r10, r8
        adoxq	r11, r9
        movq	[%rsp+160], r10
        movq	r12, rsi
        movq	r13, rbx
        movq	r14, [%rcx+192]
        movq	r10, [%rcx+200]
        ; A[13] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[13] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	[%rsp+168], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[13] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	rsi, r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[13] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	rbx, r13
        adcxq	r14, r8
        adoxq	r10, r9
        movq	[%rcx+192], r14
        movq	r11, [%rcx+208]
        movq	r12, [%rcx+216]
        movq	r13, [%rcx+224]
        movq	r14, [%rcx+232]
        ; A[13] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[13] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	[%rcx+200], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[13] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	[%rcx+208], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[13] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	[%rcx+216], r12
        adcxq	r13, r8
        adoxq	r14, r9
        movq	[%rcx+224], r13
        movq	r10, [%rcx+240]
        movq	r11, [%rcx+248]
        movq	r12, [%rcx+256]
        movq	r13, [%rcx+264]
        ; A[13] * B[16]
        mulx	r9, r8, [%rbp+128]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[13] * B[17]
        mulx	r9, r8, [%rbp+136]
        movq	[%rcx+232], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[13] * B[18]
        mulx	r9, r8, [%rbp+144]
        movq	[%rcx+240], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[13] * B[19]
        mulx	r9, r8, [%rbp+152]
        movq	[%rcx+248], r11
        adcxq	r12, r8
        adoxq	r13, r9
        movq	[%rcx+256], r12
        movq	r14, [%rcx+272]
        movq	r10, [%rcx+280]
        movq	r11, [%rcx+288]
        ; A[13] * B[20]
        mulx	r9, r8, [%rbp+160]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[13] * B[21]
        mulx	r9, r8, [%rbp+168]
        movq	[%rcx+264], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[13] * B[22]
        mulx	r9, r8, [%rbp+176]
        movq	[%rcx+272], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[13] * B[23]
        mulx	r9, r8, [%rbp+184]
        movq	[%rcx+280], r10
        movq	r12, rdi
        adcxq	r11, r8
        adoxq	r12, r9
        adcxq	r12, r15
        movq	r15, rdi
        adoxq	r15, rdi
        adcxq	r15, rdi
        movq	[%rcx+288], r11
        movq	[%rcx+296], r12
        movq	rdx, [%rax+112]
        movq	r14, [%rsp+112]
        movq	r10, [%rsp+120]
        movq	r11, [%rsp+128]
        movq	r12, [%rsp+136]
        movq	r13, [%rsp+144]
        ; A[14] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[14] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	[%rsp+112], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[14] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	[%rsp+120], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[14] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	[%rsp+128], r11
        adcxq	r12, r8
        adoxq	r13, r9
        movq	[%rsp+136], r12
        movq	r14, [%rsp+152]
        movq	r10, [%rsp+160]
        movq	r11, [%rsp+168]
        movq	r12, rsi
        ; A[14] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[14] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	[%rsp+144], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[14] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	[%rsp+152], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[14] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	[%rsp+160], r10
        adcxq	r11, r8
        adoxq	r12, r9
        movq	[%rsp+168], r11
        movq	r13, rbx
        movq	r14, [%rcx+192]
        movq	r10, [%rcx+200]
        movq	r11, [%rcx+208]
        ; A[14] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[14] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	rsi, r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[14] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	rbx, r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[14] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	[%rcx+192], r14
        adcxq	r10, r8
        adoxq	r11, r9
        movq	[%rcx+200], r10
        movq	r12, [%rcx+216]
        movq	r13, [%rcx+224]
        movq	r14, [%rcx+232]
        movq	r10, [%rcx+240]
        ; A[14] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[14] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	[%rcx+208], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[14] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	[%rcx+216], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[14] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	[%rcx+224], r13
        adcxq	r14, r8
        adoxq	r10, r9
        movq	[%rcx+232], r14
        movq	r11, [%rcx+248]
        movq	r12, [%rcx+256]
        movq	r13, [%rcx+264]
        movq	r14, [%rcx+272]
        ; A[14] * B[16]
        mulx	r9, r8, [%rbp+128]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[14] * B[17]
        mulx	r9, r8, [%rbp+136]
        movq	[%rcx+240], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[14] * B[18]
        mulx	r9, r8, [%rbp+144]
        movq	[%rcx+248], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[14] * B[19]
        mulx	r9, r8, [%rbp+152]
        movq	[%rcx+256], r12
        adcxq	r13, r8
        adoxq	r14, r9
        movq	[%rcx+264], r13
        movq	r10, [%rcx+280]
        movq	r11, [%rcx+288]
        movq	r12, [%rcx+296]
        ; A[14] * B[20]
        mulx	r9, r8, [%rbp+160]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[14] * B[21]
        mulx	r9, r8, [%rbp+168]
        movq	[%rcx+272], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[14] * B[22]
        mulx	r9, r8, [%rbp+176]
        movq	[%rcx+280], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[14] * B[23]
        mulx	r9, r8, [%rbp+184]
        movq	[%rcx+288], r11
        movq	r13, rdi
        adcxq	r12, r8
        adoxq	r13, r9
        adcxq	r13, r15
        movq	r15, rdi
        adoxq	r15, rdi
        adcxq	r15, rdi
        movq	[%rcx+296], r12
        movq	[%rcx+304], r13
        movq	rdx, [%rax+120]
        movq	r10, [%rsp+120]
        movq	r11, [%rsp+128]
        movq	r12, [%rsp+136]
        movq	r13, [%rsp+144]
        movq	r14, [%rsp+152]
        ; A[15] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[15] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	[%rsp+120], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[15] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	[%rsp+128], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[15] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	[%rsp+136], r12
        adcxq	r13, r8
        adoxq	r14, r9
        movq	[%rsp+144], r13
        movq	r10, [%rsp+160]
        movq	r11, [%rsp+168]
        movq	r12, rsi
        movq	r13, rbx
        ; A[15] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[15] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	[%rsp+152], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[15] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	[%rsp+160], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[15] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	[%rsp+168], r11
        adcxq	r12, r8
        adoxq	r13, r9
        movq	rsi, r12
        movq	r14, [%rcx+192]
        movq	r10, [%rcx+200]
        movq	r11, [%rcx+208]
        movq	r12, [%rcx+216]
        ; A[15] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[15] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	rbx, r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[15] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	[%rcx+192], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[15] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	[%rcx+200], r10
        adcxq	r11, r8
        adoxq	r12, r9
        movq	[%rcx+208], r11
        movq	r13, [%rcx+224]
        movq	r14, [%rcx+232]
        movq	r10, [%rcx+240]
        movq	r11, [%rcx+248]
        ; A[15] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[15] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	[%rcx+216], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[15] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	[%rcx+224], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[15] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	[%rcx+232], r14
        adcxq	r10, r8
        adoxq	r11, r9
        movq	[%rcx+240], r10
        movq	r12, [%rcx+256]
        movq	r13, [%rcx+264]
        movq	r14, [%rcx+272]
        movq	r10, [%rcx+280]
        ; A[15] * B[16]
        mulx	r9, r8, [%rbp+128]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[15] * B[17]
        mulx	r9, r8, [%rbp+136]
        movq	[%rcx+248], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[15] * B[18]
        mulx	r9, r8, [%rbp+144]
        movq	[%rcx+256], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[15] * B[19]
        mulx	r9, r8, [%rbp+152]
        movq	[%rcx+264], r13
        adcxq	r14, r8
        adoxq	r10, r9
        movq	[%rcx+272], r14
        movq	r11, [%rcx+288]
        movq	r12, [%rcx+296]
        movq	r13, [%rcx+304]
        ; A[15] * B[20]
        mulx	r9, r8, [%rbp+160]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[15] * B[21]
        mulx	r9, r8, [%rbp+168]
        movq	[%rcx+280], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[15] * B[22]
        mulx	r9, r8, [%rbp+176]
        movq	[%rcx+288], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[15] * B[23]
        mulx	r9, r8, [%rbp+184]
        movq	[%rcx+296], r12
        movq	r14, rdi
        adcxq	r13, r8
        adoxq	r14, r9
        adcxq	r14, r15
        movq	r15, rdi
        adoxq	r15, rdi
        adcxq	r15, rdi
        movq	[%rcx+304], r13
        movq	[%rcx+312], r14
        movq	rdx, [%rax+128]
        movq	r11, [%rsp+128]
        movq	r12, [%rsp+136]
        movq	r13, [%rsp+144]
        movq	r14, [%rsp+152]
        movq	r10, [%rsp+160]
        ; A[16] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[16] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	[%rsp+128], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[16] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	[%rsp+136], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[16] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	[%rsp+144], r13
        adcxq	r14, r8
        adoxq	r10, r9
        movq	[%rsp+152], r14
        movq	r11, [%rsp+168]
        movq	r12, rsi
        movq	r13, rbx
        movq	r14, [%rcx+192]
        ; A[16] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[16] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	[%rsp+160], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[16] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	[%rsp+168], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[16] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	rsi, r12
        adcxq	r13, r8
        adoxq	r14, r9
        movq	rbx, r13
        movq	r10, [%rcx+200]
        movq	r11, [%rcx+208]
        movq	r12, [%rcx+216]
        movq	r13, [%rcx+224]
        ; A[16] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[16] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	[%rcx+192], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[16] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	[%rcx+200], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[16] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	[%rcx+208], r11
        adcxq	r12, r8
        adoxq	r13, r9
        movq	[%rcx+216], r12
        movq	r14, [%rcx+232]
        movq	r10, [%rcx+240]
        movq	r11, [%rcx+248]
        movq	r12, [%rcx+256]
        ; A[16] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[16] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	[%rcx+224], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[16] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	[%rcx+232], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[16] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	[%rcx+240], r10
        adcxq	r11, r8
        adoxq	r12, r9
        movq	[%rcx+248], r11
        movq	r13, [%rcx+264]
        movq	r14, [%rcx+272]
        movq	r10, [%rcx+280]
        movq	r11, [%rcx+288]
        ; A[16] * B[16]
        mulx	r9, r8, [%rbp+128]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[16] * B[17]
        mulx	r9, r8, [%rbp+136]
        movq	[%rcx+256], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[16] * B[18]
        mulx	r9, r8, [%rbp+144]
        movq	[%rcx+264], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[16] * B[19]
        mulx	r9, r8, [%rbp+152]
        movq	[%rcx+272], r14
        adcxq	r10, r8
        adoxq	r11, r9
        movq	[%rcx+280], r10
        movq	r12, [%rcx+296]
        movq	r13, [%rcx+304]
        movq	r14, [%rcx+312]
        ; A[16] * B[20]
        mulx	r9, r8, [%rbp+160]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[16] * B[21]
        mulx	r9, r8, [%rbp+168]
        movq	[%rcx+288], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[16] * B[22]
        mulx	r9, r8, [%rbp+176]
        movq	[%rcx+296], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[16] * B[23]
        mulx	r9, r8, [%rbp+184]
        movq	[%rcx+304], r13
        movq	r10, rdi
        adcxq	r14, r8
        adoxq	r10, r9
        adcxq	r10, r15
        movq	r15, rdi
        adoxq	r15, rdi
        adcxq	r15, rdi
        movq	[%rcx+312], r14
        movq	[%rcx+320], r10
        movq	rdx, [%rax+136]
        movq	r12, [%rsp+136]
        movq	r13, [%rsp+144]
        movq	r14, [%rsp+152]
        movq	r10, [%rsp+160]
        movq	r11, [%rsp+168]
        ; A[17] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[17] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	[%rsp+136], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[17] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	[%rsp+144], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[17] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	[%rsp+152], r14
        adcxq	r10, r8
        adoxq	r11, r9
        movq	[%rsp+160], r10
        movq	r12, rsi
        movq	r13, rbx
        movq	r14, [%rcx+192]
        movq	r10, [%rcx+200]
        ; A[17] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[17] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	[%rsp+168], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[17] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	rsi, r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[17] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	rbx, r13
        adcxq	r14, r8
        adoxq	r10, r9
        movq	[%rcx+192], r14
        movq	r11, [%rcx+208]
        movq	r12, [%rcx+216]
        movq	r13, [%rcx+224]
        movq	r14, [%rcx+232]
        ; A[17] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[17] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	[%rcx+200], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[17] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	[%rcx+208], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[17] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	[%rcx+216], r12
        adcxq	r13, r8
        adoxq	r14, r9
        movq	[%rcx+224], r13
        movq	r10, [%rcx+240]
        movq	r11, [%rcx+248]
        movq	r12, [%rcx+256]
        movq	r13, [%rcx+264]
        ; A[17] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[17] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	[%rcx+232], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[17] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	[%rcx+240], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[17] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	[%rcx+248], r11
        adcxq	r12, r8
        adoxq	r13, r9
        movq	[%rcx+256], r12
        movq	r14, [%rcx+272]
        movq	r10, [%rcx+280]
        movq	r11, [%rcx+288]
        movq	r12, [%rcx+296]
        ; A[17] * B[16]
        mulx	r9, r8, [%rbp+128]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[17] * B[17]
        mulx	r9, r8, [%rbp+136]
        movq	[%rcx+264], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[17] * B[18]
        mulx	r9, r8, [%rbp+144]
        movq	[%rcx+272], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[17] * B[19]
        mulx	r9, r8, [%rbp+152]
        movq	[%rcx+280], r10
        adcxq	r11, r8
        adoxq	r12, r9
        movq	[%rcx+288], r11
        movq	r13, [%rcx+304]
        movq	r14, [%rcx+312]
        movq	r10, [%rcx+320]
        ; A[17] * B[20]
        mulx	r9, r8, [%rbp+160]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[17] * B[21]
        mulx	r9, r8, [%rbp+168]
        movq	[%rcx+296], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[17] * B[22]
        mulx	r9, r8, [%rbp+176]
        movq	[%rcx+304], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[17] * B[23]
        mulx	r9, r8, [%rbp+184]
        movq	[%rcx+312], r14
        movq	r11, rdi
        adcxq	r10, r8
        adoxq	r11, r9
        adcxq	r11, r15
        movq	r15, rdi
        adoxq	r15, rdi
        adcxq	r15, rdi
        movq	[%rcx+320], r10
        movq	[%rcx+328], r11
        movq	rdx, [%rax+144]
        movq	r13, [%rsp+144]
        movq	r14, [%rsp+152]
        movq	r10, [%rsp+160]
        movq	r11, [%rsp+168]
        movq	r12, rsi
        ; A[18] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[18] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	[%rsp+144], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[18] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	[%rsp+152], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[18] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	[%rsp+160], r10
        adcxq	r11, r8
        adoxq	r12, r9
        movq	[%rsp+168], r11
        movq	r13, rbx
        movq	r14, [%rcx+192]
        movq	r10, [%rcx+200]
        movq	r11, [%rcx+208]
        ; A[18] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[18] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	rsi, r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[18] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	rbx, r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[18] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	[%rcx+192], r14
        adcxq	r10, r8
        adoxq	r11, r9
        movq	[%rcx+200], r10
        movq	r12, [%rcx+216]
        movq	r13, [%rcx+224]
        movq	r14, [%rcx+232]
        movq	r10, [%rcx+240]
        ; A[18] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[18] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	[%rcx+208], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[18] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	[%rcx+216], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[18] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	[%rcx+224], r13
        adcxq	r14, r8
        adoxq	r10, r9
        movq	[%rcx+232], r14
        movq	r11, [%rcx+248]
        movq	r12, [%rcx+256]
        movq	r13, [%rcx+264]
        movq	r14, [%rcx+272]
        ; A[18] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[18] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	[%rcx+240], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[18] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	[%rcx+248], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[18] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	[%rcx+256], r12
        adcxq	r13, r8
        adoxq	r14, r9
        movq	[%rcx+264], r13
        movq	r10, [%rcx+280]
        movq	r11, [%rcx+288]
        movq	r12, [%rcx+296]
        movq	r13, [%rcx+304]
        ; A[18] * B[16]
        mulx	r9, r8, [%rbp+128]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[18] * B[17]
        mulx	r9, r8, [%rbp+136]
        movq	[%rcx+272], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[18] * B[18]
        mulx	r9, r8, [%rbp+144]
        movq	[%rcx+280], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[18] * B[19]
        mulx	r9, r8, [%rbp+152]
        movq	[%rcx+288], r11
        adcxq	r12, r8
        adoxq	r13, r9
        movq	[%rcx+296], r12
        movq	r14, [%rcx+312]
        movq	r10, [%rcx+320]
        movq	r11, [%rcx+328]
        ; A[18] * B[20]
        mulx	r9, r8, [%rbp+160]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[18] * B[21]
        mulx	r9, r8, [%rbp+168]
        movq	[%rcx+304], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[18] * B[22]
        mulx	r9, r8, [%rbp+176]
        movq	[%rcx+312], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[18] * B[23]
        mulx	r9, r8, [%rbp+184]
        movq	[%rcx+320], r10
        movq	r12, rdi
        adcxq	r11, r8
        adoxq	r12, r9
        adcxq	r12, r15
        movq	r15, rdi
        adoxq	r15, rdi
        adcxq	r15, rdi
        movq	[%rcx+328], r11
        movq	[%rcx+336], r12
        movq	rdx, [%rax+152]
        movq	r14, [%rsp+152]
        movq	r10, [%rsp+160]
        movq	r11, [%rsp+168]
        movq	r12, rsi
        movq	r13, rbx
        ; A[19] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[19] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	[%rsp+152], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[19] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	[%rsp+160], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[19] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	[%rsp+168], r11
        adcxq	r12, r8
        adoxq	r13, r9
        movq	rsi, r12
        movq	r14, [%rcx+192]
        movq	r10, [%rcx+200]
        movq	r11, [%rcx+208]
        movq	r12, [%rcx+216]
        ; A[19] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[19] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	rbx, r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[19] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	[%rcx+192], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[19] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	[%rcx+200], r10
        adcxq	r11, r8
        adoxq	r12, r9
        movq	[%rcx+208], r11
        movq	r13, [%rcx+224]
        movq	r14, [%rcx+232]
        movq	r10, [%rcx+240]
        movq	r11, [%rcx+248]
        ; A[19] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[19] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	[%rcx+216], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[19] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	[%rcx+224], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[19] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	[%rcx+232], r14
        adcxq	r10, r8
        adoxq	r11, r9
        movq	[%rcx+240], r10
        movq	r12, [%rcx+256]
        movq	r13, [%rcx+264]
        movq	r14, [%rcx+272]
        movq	r10, [%rcx+280]
        ; A[19] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[19] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	[%rcx+248], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[19] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	[%rcx+256], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[19] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	[%rcx+264], r13
        adcxq	r14, r8
        adoxq	r10, r9
        movq	[%rcx+272], r14
        movq	r11, [%rcx+288]
        movq	r12, [%rcx+296]
        movq	r13, [%rcx+304]
        movq	r14, [%rcx+312]
        ; A[19] * B[16]
        mulx	r9, r8, [%rbp+128]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[19] * B[17]
        mulx	r9, r8, [%rbp+136]
        movq	[%rcx+280], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[19] * B[18]
        mulx	r9, r8, [%rbp+144]
        movq	[%rcx+288], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[19] * B[19]
        mulx	r9, r8, [%rbp+152]
        movq	[%rcx+296], r12
        adcxq	r13, r8
        adoxq	r14, r9
        movq	[%rcx+304], r13
        movq	r10, [%rcx+320]
        movq	r11, [%rcx+328]
        movq	r12, [%rcx+336]
        ; A[19] * B[20]
        mulx	r9, r8, [%rbp+160]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[19] * B[21]
        mulx	r9, r8, [%rbp+168]
        movq	[%rcx+312], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[19] * B[22]
        mulx	r9, r8, [%rbp+176]
        movq	[%rcx+320], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[19] * B[23]
        mulx	r9, r8, [%rbp+184]
        movq	[%rcx+328], r11
        movq	r13, rdi
        adcxq	r12, r8
        adoxq	r13, r9
        adcxq	r13, r15
        movq	r15, rdi
        adoxq	r15, rdi
        adcxq	r15, rdi
        movq	[%rcx+336], r12
        movq	[%rcx+344], r13
        movq	rdx, [%rax+160]
        movq	r10, [%rsp+160]
        movq	r11, [%rsp+168]
        movq	r12, rsi
        movq	r13, rbx
        movq	r14, [%rcx+192]
        ; A[20] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[20] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	[%rsp+160], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[20] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	[%rsp+168], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[20] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	rsi, r12
        adcxq	r13, r8
        adoxq	r14, r9
        movq	rbx, r13
        movq	r10, [%rcx+200]
        movq	r11, [%rcx+208]
        movq	r12, [%rcx+216]
        movq	r13, [%rcx+224]
        ; A[20] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[20] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	[%rcx+192], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[20] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	[%rcx+200], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[20] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	[%rcx+208], r11
        adcxq	r12, r8
        adoxq	r13, r9
        movq	[%rcx+216], r12
        movq	r14, [%rcx+232]
        movq	r10, [%rcx+240]
        movq	r11, [%rcx+248]
        movq	r12, [%rcx+256]
        ; A[20] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[20] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	[%rcx+224], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[20] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	[%rcx+232], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[20] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	[%rcx+240], r10
        adcxq	r11, r8
        adoxq	r12, r9
        movq	[%rcx+248], r11
        movq	r13, [%rcx+264]
        movq	r14, [%rcx+272]
        movq	r10, [%rcx+280]
        movq	r11, [%rcx+288]
        ; A[20] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[20] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	[%rcx+256], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[20] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	[%rcx+264], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[20] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	[%rcx+272], r14
        adcxq	r10, r8
        adoxq	r11, r9
        movq	[%rcx+280], r10
        movq	r12, [%rcx+296]
        movq	r13, [%rcx+304]
        movq	r14, [%rcx+312]
        movq	r10, [%rcx+320]
        ; A[20] * B[16]
        mulx	r9, r8, [%rbp+128]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[20] * B[17]
        mulx	r9, r8, [%rbp+136]
        movq	[%rcx+288], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[20] * B[18]
        mulx	r9, r8, [%rbp+144]
        movq	[%rcx+296], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[20] * B[19]
        mulx	r9, r8, [%rbp+152]
        movq	[%rcx+304], r13
        adcxq	r14, r8
        adoxq	r10, r9
        movq	[%rcx+312], r14
        movq	r11, [%rcx+328]
        movq	r12, [%rcx+336]
        movq	r13, [%rcx+344]
        ; A[20] * B[20]
        mulx	r9, r8, [%rbp+160]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[20] * B[21]
        mulx	r9, r8, [%rbp+168]
        movq	[%rcx+320], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[20] * B[22]
        mulx	r9, r8, [%rbp+176]
        movq	[%rcx+328], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[20] * B[23]
        mulx	r9, r8, [%rbp+184]
        movq	[%rcx+336], r12
        movq	r14, rdi
        adcxq	r13, r8
        adoxq	r14, r9
        adcxq	r14, r15
        movq	r15, rdi
        adoxq	r15, rdi
        adcxq	r15, rdi
        movq	[%rcx+344], r13
        movq	[%rcx+352], r14
        movq	rdx, [%rax+168]
        movq	r11, [%rsp+168]
        movq	r12, rsi
        movq	r13, rbx
        movq	r14, [%rcx+192]
        movq	r10, [%rcx+200]
        ; A[21] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[21] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	[%rsp+168], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[21] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	rsi, r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[21] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	rbx, r13
        adcxq	r14, r8
        adoxq	r10, r9
        movq	[%rcx+192], r14
        movq	r11, [%rcx+208]
        movq	r12, [%rcx+216]
        movq	r13, [%rcx+224]
        movq	r14, [%rcx+232]
        ; A[21] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[21] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	[%rcx+200], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[21] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	[%rcx+208], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[21] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	[%rcx+216], r12
        adcxq	r13, r8
        adoxq	r14, r9
        movq	[%rcx+224], r13
        movq	r10, [%rcx+240]
        movq	r11, [%rcx+248]
        movq	r12, [%rcx+256]
        movq	r13, [%rcx+264]
        ; A[21] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[21] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	[%rcx+232], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[21] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	[%rcx+240], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[21] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	[%rcx+248], r11
        adcxq	r12, r8
        adoxq	r13, r9
        movq	[%rcx+256], r12
        movq	r14, [%rcx+272]
        movq	r10, [%rcx+280]
        movq	r11, [%rcx+288]
        movq	r12, [%rcx+296]
        ; A[21] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[21] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	[%rcx+264], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[21] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	[%rcx+272], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[21] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	[%rcx+280], r10
        adcxq	r11, r8
        adoxq	r12, r9
        movq	[%rcx+288], r11
        movq	r13, [%rcx+304]
        movq	r14, [%rcx+312]
        movq	r10, [%rcx+320]
        movq	r11, [%rcx+328]
        ; A[21] * B[16]
        mulx	r9, r8, [%rbp+128]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[21] * B[17]
        mulx	r9, r8, [%rbp+136]
        movq	[%rcx+296], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[21] * B[18]
        mulx	r9, r8, [%rbp+144]
        movq	[%rcx+304], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[21] * B[19]
        mulx	r9, r8, [%rbp+152]
        movq	[%rcx+312], r14
        adcxq	r10, r8
        adoxq	r11, r9
        movq	[%rcx+320], r10
        movq	r12, [%rcx+336]
        movq	r13, [%rcx+344]
        movq	r14, [%rcx+352]
        ; A[21] * B[20]
        mulx	r9, r8, [%rbp+160]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[21] * B[21]
        mulx	r9, r8, [%rbp+168]
        movq	[%rcx+328], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[21] * B[22]
        mulx	r9, r8, [%rbp+176]
        movq	[%rcx+336], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[21] * B[23]
        mulx	r9, r8, [%rbp+184]
        movq	[%rcx+344], r13
        movq	r10, rdi
        adcxq	r14, r8
        adoxq	r10, r9
        adcxq	r10, r15
        movq	r15, rdi
        adoxq	r15, rdi
        adcxq	r15, rdi
        movq	[%rcx+352], r14
        movq	[%rcx+360], r10
        movq	rdx, [%rax+176]
        movq	r12, rsi
        movq	r13, rbx
        movq	r14, [%rcx+192]
        movq	r10, [%rcx+200]
        movq	r11, [%rcx+208]
        ; A[22] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[22] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	rsi, r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[22] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	rbx, r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[22] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	[%rcx+192], r14
        adcxq	r10, r8
        adoxq	r11, r9
        movq	[%rcx+200], r10
        movq	r12, [%rcx+216]
        movq	r13, [%rcx+224]
        movq	r14, [%rcx+232]
        movq	r10, [%rcx+240]
        ; A[22] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[22] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	[%rcx+208], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[22] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	[%rcx+216], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[22] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	[%rcx+224], r13
        adcxq	r14, r8
        adoxq	r10, r9
        movq	[%rcx+232], r14
        movq	r11, [%rcx+248]
        movq	r12, [%rcx+256]
        movq	r13, [%rcx+264]
        movq	r14, [%rcx+272]
        ; A[22] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[22] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	[%rcx+240], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[22] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	[%rcx+248], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[22] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	[%rcx+256], r12
        adcxq	r13, r8
        adoxq	r14, r9
        movq	[%rcx+264], r13
        movq	r10, [%rcx+280]
        movq	r11, [%rcx+288]
        movq	r12, [%rcx+296]
        movq	r13, [%rcx+304]
        ; A[22] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[22] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	[%rcx+272], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[22] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	[%rcx+280], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[22] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	[%rcx+288], r11
        adcxq	r12, r8
        adoxq	r13, r9
        movq	[%rcx+296], r12
        movq	r14, [%rcx+312]
        movq	r10, [%rcx+320]
        movq	r11, [%rcx+328]
        movq	r12, [%rcx+336]
        ; A[22] * B[16]
        mulx	r9, r8, [%rbp+128]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[22] * B[17]
        mulx	r9, r8, [%rbp+136]
        movq	[%rcx+304], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[22] * B[18]
        mulx	r9, r8, [%rbp+144]
        movq	[%rcx+312], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[22] * B[19]
        mulx	r9, r8, [%rbp+152]
        movq	[%rcx+320], r10
        adcxq	r11, r8
        adoxq	r12, r9
        movq	[%rcx+328], r11
        movq	r13, [%rcx+344]
        movq	r14, [%rcx+352]
        movq	r10, [%rcx+360]
        ; A[22] * B[20]
        mulx	r9, r8, [%rbp+160]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[22] * B[21]
        mulx	r9, r8, [%rbp+168]
        movq	[%rcx+336], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[22] * B[22]
        mulx	r9, r8, [%rbp+176]
        movq	[%rcx+344], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[22] * B[23]
        mulx	r9, r8, [%rbp+184]
        movq	[%rcx+352], r14
        movq	r11, rdi
        adcxq	r10, r8
        adoxq	r11, r9
        adcxq	r11, r15
        movq	r15, rdi
        adoxq	r15, rdi
        adcxq	r15, rdi
        movq	[%rcx+360], r10
        movq	[%rcx+368], r11
        movq	rdx, [%rax+184]
        movq	r13, rbx
        movq	r14, [%rcx+192]
        movq	r10, [%rcx+200]
        movq	r11, [%rcx+208]
        movq	r12, [%rcx+216]
        ; A[23] * B[0]
        mulx	r9, r8, [%rbp]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[23] * B[1]
        mulx	r9, r8, [%rbp+8]
        movq	rbx, r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[23] * B[2]
        mulx	r9, r8, [%rbp+16]
        movq	[%rcx+192], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[23] * B[3]
        mulx	r9, r8, [%rbp+24]
        movq	[%rcx+200], r10
        adcxq	r11, r8
        adoxq	r12, r9
        movq	[%rcx+208], r11
        movq	r13, [%rcx+224]
        movq	r14, [%rcx+232]
        movq	r10, [%rcx+240]
        movq	r11, [%rcx+248]
        ; A[23] * B[4]
        mulx	r9, r8, [%rbp+32]
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[23] * B[5]
        mulx	r9, r8, [%rbp+40]
        movq	[%rcx+216], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[23] * B[6]
        mulx	r9, r8, [%rbp+48]
        movq	[%rcx+224], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[23] * B[7]
        mulx	r9, r8, [%rbp+56]
        movq	[%rcx+232], r14
        adcxq	r10, r8
        adoxq	r11, r9
        movq	[%rcx+240], r10
        movq	r12, [%rcx+256]
        movq	r13, [%rcx+264]
        movq	r14, [%rcx+272]
        movq	r10, [%rcx+280]
        ; A[23] * B[8]
        mulx	r9, r8, [%rbp+64]
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[23] * B[9]
        mulx	r9, r8, [%rbp+72]
        movq	[%rcx+248], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[23] * B[10]
        mulx	r9, r8, [%rbp+80]
        movq	[%rcx+256], r12
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[23] * B[11]
        mulx	r9, r8, [%rbp+88]
        movq	[%rcx+264], r13
        adcxq	r14, r8
        adoxq	r10, r9
        movq	[%rcx+272], r14
        movq	r11, [%rcx+288]
        movq	r12, [%rcx+296]
        movq	r13, [%rcx+304]
        movq	r14, [%rcx+312]
        ; A[23] * B[12]
        mulx	r9, r8, [%rbp+96]
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[23] * B[13]
        mulx	r9, r8, [%rbp+104]
        movq	[%rcx+280], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[23] * B[14]
        mulx	r9, r8, [%rbp+112]
        movq	[%rcx+288], r11
        adcxq	r12, r8
        adoxq	r13, r9
        ; A[23] * B[15]
        mulx	r9, r8, [%rbp+120]
        movq	[%rcx+296], r12
        adcxq	r13, r8
        adoxq	r14, r9
        movq	[%rcx+304], r13
        movq	r10, [%rcx+320]
        movq	r11, [%rcx+328]
        movq	r12, [%rcx+336]
        movq	r13, [%rcx+344]
        ; A[23] * B[16]
        mulx	r9, r8, [%rbp+128]
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[23] * B[17]
        mulx	r9, r8, [%rbp+136]
        movq	[%rcx+312], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[23] * B[18]
        mulx	r9, r8, [%rbp+144]
        movq	[%rcx+320], r10
        adcxq	r11, r8
        adoxq	r12, r9
        ; A[23] * B[19]
        mulx	r9, r8, [%rbp+152]
        movq	[%rcx+328], r11
        adcxq	r12, r8
        adoxq	r13, r9
        movq	[%rcx+336], r12
        movq	r14, [%rcx+352]
        movq	r10, [%rcx+360]
        movq	r11, [%rcx+368]
        ; A[23] * B[20]
        mulx	r9, r8, [%rbp+160]
        adcxq	r13, r8
        adoxq	r14, r9
        ; A[23] * B[21]
        mulx	r9, r8, [%rbp+168]
        movq	[%rcx+344], r13
        adcxq	r14, r8
        adoxq	r10, r9
        ; A[23] * B[22]
        mulx	r9, r8, [%rbp+176]
        movq	[%rcx+352], r14
        adcxq	r10, r8
        adoxq	r11, r9
        ; A[23] * B[23]
        mulx	r9, r8, [%rbp+184]
        movq	[%rcx+360], r10
        movq	r12, rdi
        adcxq	r11, r8
        adoxq	r12, r9
        adcxq	r12, r15
        movq	[%rcx+368], r11
        movq	[%rcx+376], r12
        movq	r10, [%rsp]
        movq	r11, [%rsp+8]
        movq	r12, [%rsp+16]
        movq	r13, [%rsp+24]
        movq	[%rcx], r10
        movq	[%rcx+8], r11
        movq	[%rcx+16], r12
        movq	[%rcx+24], r13
        movq	r10, [%rsp+32]
        movq	r11, [%rsp+40]
        movq	r12, [%rsp+48]
        movq	r13, [%rsp+56]
        movq	[%rcx+32], r10
        movq	[%rcx+40], r11
        movq	[%rcx+48], r12
        movq	[%rcx+56], r13
        movq	r10, [%rsp+64]
        movq	r11, [%rsp+72]
        movq	r12, [%rsp+80]
        movq	r13, [%rsp+88]
        movq	[%rcx+64], r10
        movq	[%rcx+72], r11
        movq	[%rcx+80], r12
        movq	[%rcx+88], r13
        movq	r10, [%rsp+96]
        movq	r11, [%rsp+104]
        movq	r12, [%rsp+112]
        movq	r13, [%rsp+120]
        movq	[%rcx+96], r10
        movq	[%rcx+104], r11
        movq	[%rcx+112], r12
        movq	[%rcx+120], r13
        movq	r10, [%rsp+128]
        movq	r11, [%rsp+136]
        movq	r12, [%rsp+144]
        movq	r13, [%rsp+152]
        movq	[%rcx+128], r10
        movq	[%rcx+136], r11
        movq	[%rcx+144], r12
        movq	[%rcx+152], r13
        movq	r10, [%rsp+160]
        movq	r11, [%rsp+168]
        movq	r12, rsi
        movq	r13, rbx
        movq	[%rcx+160], r10
        movq	[%rcx+168], r11
        movq	[%rcx+176], r12
        movq	[%rcx+184], r13
        addq	rsp, 192
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rbp
        repz retq
sp_3072_mul_avx2_24 ENDP
ENDIF
IFDEF HAVE_INTEL_AVX2
; /* Square a and put result in r. (r = a * a)
;  *
;  * r  A single precision integer.
;  * a  A single precision integer.
;  */
sp_3072_sqr_avx2_24 PROC
        movq	r8, rdx
        movq	r9, rcx
        push	rbp
        push	r12
        push	r13
        push	r14
        push	r15
        subq	rsp, 192
        cmpq	r8, r9
        movq	rbp, rsp
        cmovne	rbp, r9
        xorq	r14, r14
        ; Diagonal 1
        xorq	r10, r10
        xorq	r11, r11
        xorq	r12, r12
        xorq	r13, r13
        ; A[1] x A[0]
        movq	rdx, [%r8]
        mulxq	r11, r10, [%r8+8]
        ; A[2] x A[0]
        mulxq	rcx, rax, [%r8+16]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[3] x A[0]
        mulxq	rcx, rax, [%r8+24]
        adcxq	r12, rax
        adoxq	r13, rcx
        movq	[%rbp+8], r10
        movq	[%rbp+16], r11
        movq	[%rbp+24], r12
        movq	r10, r14
        movq	r11, r14
        movq	r12, r14
        ; A[4] x A[0]
        mulxq	rcx, rax, [%r8+32]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[5] x A[0]
        mulxq	rcx, rax, [%r8+40]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[6] x A[0]
        mulxq	rcx, rax, [%r8+48]
        adcxq	r11, rax
        adoxq	r12, rcx
        movq	[%rbp+32], r13
        movq	[%rbp+40], r10
        movq	[%rbp+48], r11
        movq	r13, r14
        movq	r10, r14
        movq	r11, r14
        ; A[7] x A[0]
        mulxq	rcx, rax, [%r8+56]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[8] x A[0]
        mulxq	rcx, rax, [%r8+64]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[9] x A[0]
        mulxq	rcx, rax, [%r8+72]
        adcxq	r10, rax
        adoxq	r11, rcx
        movq	[%rbp+56], r12
        movq	[%rbp+64], r13
        movq	[%rbp+72], r10
        movq	r12, r14
        movq	r13, r14
        movq	r10, r14
        ; A[10] x A[0]
        mulxq	rcx, rax, [%r8+80]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[11] x A[0]
        mulxq	rcx, rax, [%r8+88]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[12] x A[0]
        mulxq	rcx, rax, [%r8+96]
        adcxq	r13, rax
        adoxq	r10, rcx
        movq	[%rbp+80], r11
        movq	[%rbp+88], r12
        movq	[%rbp+96], r13
        movq	r11, r14
        movq	r12, r14
        movq	r13, r14
        ; A[13] x A[0]
        mulxq	rcx, rax, [%r8+104]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[14] x A[0]
        mulxq	rcx, rax, [%r8+112]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[15] x A[0]
        mulxq	rcx, rax, [%r8+120]
        adcxq	r12, rax
        adoxq	r13, rcx
        movq	[%rbp+104], r10
        movq	[%rbp+112], r11
        movq	[%rbp+120], r12
        movq	r10, r14
        movq	r11, r14
        movq	r12, r14
        ; A[16] x A[0]
        mulxq	rcx, rax, [%r8+128]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[17] x A[0]
        mulxq	rcx, rax, [%r8+136]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[18] x A[0]
        mulxq	rcx, rax, [%r8+144]
        adcxq	r11, rax
        adoxq	r12, rcx
        movq	[%rbp+128], r13
        movq	[%rbp+136], r10
        movq	[%rbp+144], r11
        movq	r13, r14
        movq	r10, r14
        movq	r11, r14
        ; A[19] x A[0]
        mulxq	rcx, rax, [%r8+152]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[20] x A[0]
        mulxq	rcx, rax, [%r8+160]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[21] x A[0]
        mulxq	rcx, rax, [%r8+168]
        adcxq	r10, rax
        adoxq	r11, rcx
        movq	[%rbp+152], r12
        movq	[%rbp+160], r13
        movq	[%rbp+168], r10
        movq	r12, r14
        movq	r13, r14
        ; A[22] x A[0]
        mulxq	rcx, rax, [%r8+176]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[23] x A[0]
        mulxq	rcx, rax, [%r8+184]
        adcxq	r12, rax
        adoxq	r13, rcx
        movq	[%rbp+176], r11
        movq	[%rbp+184], r12
        ;  Carry
        adcxq	r13, r14
        movq	r15, r14
        adcxq	r15, r14
        adoxq	r15, r14
        movq	[%r9+192], r13
        ; Diagonal 2
        movq	r13, [%rbp+24]
        movq	r10, [%rbp+32]
        movq	r11, [%rbp+40]
        movq	r12, [%rbp+48]
        ; A[2] x A[1]
        movq	rdx, [%r8+8]
        mulxq	rcx, rax, [%r8+16]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[3] x A[1]
        mulxq	rcx, rax, [%r8+24]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[4] x A[1]
        mulxq	rcx, rax, [%r8+32]
        adcxq	r11, rax
        adoxq	r12, rcx
        movq	[%rbp+24], r13
        movq	[%rbp+32], r10
        movq	[%rbp+40], r11
        movq	r13, [%rbp+56]
        movq	r10, [%rbp+64]
        movq	r11, [%rbp+72]
        ; A[5] x A[1]
        mulxq	rcx, rax, [%r8+40]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[6] x A[1]
        mulxq	rcx, rax, [%r8+48]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[7] x A[1]
        mulxq	rcx, rax, [%r8+56]
        adcxq	r10, rax
        adoxq	r11, rcx
        movq	[%rbp+48], r12
        movq	[%rbp+56], r13
        movq	[%rbp+64], r10
        movq	r12, [%rbp+80]
        movq	r13, [%rbp+88]
        movq	r10, [%rbp+96]
        ; A[8] x A[1]
        mulxq	rcx, rax, [%r8+64]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[9] x A[1]
        mulxq	rcx, rax, [%r8+72]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[10] x A[1]
        mulxq	rcx, rax, [%r8+80]
        adcxq	r13, rax
        adoxq	r10, rcx
        movq	[%rbp+72], r11
        movq	[%rbp+80], r12
        movq	[%rbp+88], r13
        movq	r11, [%rbp+104]
        movq	r12, [%rbp+112]
        movq	r13, [%rbp+120]
        ; A[11] x A[1]
        mulxq	rcx, rax, [%r8+88]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[12] x A[1]
        mulxq	rcx, rax, [%r8+96]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[13] x A[1]
        mulxq	rcx, rax, [%r8+104]
        adcxq	r12, rax
        adoxq	r13, rcx
        movq	[%rbp+96], r10
        movq	[%rbp+104], r11
        movq	[%rbp+112], r12
        movq	r10, [%rbp+128]
        movq	r11, [%rbp+136]
        movq	r12, [%rbp+144]
        ; A[14] x A[1]
        mulxq	rcx, rax, [%r8+112]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[15] x A[1]
        mulxq	rcx, rax, [%r8+120]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[16] x A[1]
        mulxq	rcx, rax, [%r8+128]
        adcxq	r11, rax
        adoxq	r12, rcx
        movq	[%rbp+120], r13
        movq	[%rbp+128], r10
        movq	[%rbp+136], r11
        movq	r13, [%rbp+152]
        movq	r10, [%rbp+160]
        movq	r11, [%rbp+168]
        ; A[17] x A[1]
        mulxq	rcx, rax, [%r8+136]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[18] x A[1]
        mulxq	rcx, rax, [%r8+144]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[19] x A[1]
        mulxq	rcx, rax, [%r8+152]
        adcxq	r10, rax
        adoxq	r11, rcx
        movq	[%rbp+144], r12
        movq	[%rbp+152], r13
        movq	[%rbp+160], r10
        movq	r12, [%rbp+176]
        movq	r13, [%rbp+184]
        movq	r10, [%r9+192]
        ; A[20] x A[1]
        mulxq	rcx, rax, [%r8+160]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[21] x A[1]
        mulxq	rcx, rax, [%r8+168]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[22] x A[1]
        mulxq	rcx, rax, [%r8+176]
        adcxq	r13, rax
        adoxq	r10, rcx
        movq	[%rbp+168], r11
        movq	[%rbp+176], r12
        movq	[%rbp+184], r13
        movq	r11, r14
        movq	r12, r14
        ; A[23] x A[1]
        mulxq	rcx, rax, [%r8+184]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[23] x A[2]
        movq	rdx, [%r8+16]
        mulxq	rcx, rax, [%r8+184]
        adcxq	r11, rax
        adoxq	r12, rcx
        movq	[%r9+192], r10
        movq	[%r9+200], r11
        ;  Carry
        adcxq	r12, r15
        movq	r15, r14
        adcxq	r15, r14
        adoxq	r15, r14
        movq	[%r9+208], r12
        ; Diagonal 3
        movq	r12, [%rbp+40]
        movq	r13, [%rbp+48]
        movq	r10, [%rbp+56]
        movq	r11, [%rbp+64]
        ; A[3] x A[2]
        mulxq	rcx, rax, [%r8+24]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[4] x A[2]
        mulxq	rcx, rax, [%r8+32]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[5] x A[2]
        mulxq	rcx, rax, [%r8+40]
        adcxq	r10, rax
        adoxq	r11, rcx
        movq	[%rbp+40], r12
        movq	[%rbp+48], r13
        movq	[%rbp+56], r10
        movq	r12, [%rbp+72]
        movq	r13, [%rbp+80]
        movq	r10, [%rbp+88]
        ; A[6] x A[2]
        mulxq	rcx, rax, [%r8+48]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[7] x A[2]
        mulxq	rcx, rax, [%r8+56]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[8] x A[2]
        mulxq	rcx, rax, [%r8+64]
        adcxq	r13, rax
        adoxq	r10, rcx
        movq	[%rbp+64], r11
        movq	[%rbp+72], r12
        movq	[%rbp+80], r13
        movq	r11, [%rbp+96]
        movq	r12, [%rbp+104]
        movq	r13, [%rbp+112]
        ; A[9] x A[2]
        mulxq	rcx, rax, [%r8+72]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[10] x A[2]
        mulxq	rcx, rax, [%r8+80]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[11] x A[2]
        mulxq	rcx, rax, [%r8+88]
        adcxq	r12, rax
        adoxq	r13, rcx
        movq	[%rbp+88], r10
        movq	[%rbp+96], r11
        movq	[%rbp+104], r12
        movq	r10, [%rbp+120]
        movq	r11, [%rbp+128]
        movq	r12, [%rbp+136]
        ; A[12] x A[2]
        mulxq	rcx, rax, [%r8+96]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[13] x A[2]
        mulxq	rcx, rax, [%r8+104]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[14] x A[2]
        mulxq	rcx, rax, [%r8+112]
        adcxq	r11, rax
        adoxq	r12, rcx
        movq	[%rbp+112], r13
        movq	[%rbp+120], r10
        movq	[%rbp+128], r11
        movq	r13, [%rbp+144]
        movq	r10, [%rbp+152]
        movq	r11, [%rbp+160]
        ; A[15] x A[2]
        mulxq	rcx, rax, [%r8+120]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[16] x A[2]
        mulxq	rcx, rax, [%r8+128]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[17] x A[2]
        mulxq	rcx, rax, [%r8+136]
        adcxq	r10, rax
        adoxq	r11, rcx
        movq	[%rbp+136], r12
        movq	[%rbp+144], r13
        movq	[%rbp+152], r10
        movq	r12, [%rbp+168]
        movq	r13, [%rbp+176]
        movq	r10, [%rbp+184]
        ; A[18] x A[2]
        mulxq	rcx, rax, [%r8+144]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[19] x A[2]
        mulxq	rcx, rax, [%r8+152]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[20] x A[2]
        mulxq	rcx, rax, [%r8+160]
        adcxq	r13, rax
        adoxq	r10, rcx
        movq	[%rbp+160], r11
        movq	[%rbp+168], r12
        movq	[%rbp+176], r13
        movq	r11, [%r9+192]
        movq	r12, [%r9+200]
        movq	r13, [%r9+208]
        ; A[21] x A[2]
        mulxq	rcx, rax, [%r8+168]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[22] x A[2]
        mulxq	rcx, rax, [%r8+176]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[22] x A[3]
        movq	rdx, [%r8+176]
        mulxq	rcx, rax, [%r8+24]
        adcxq	r12, rax
        adoxq	r13, rcx
        movq	[%rbp+184], r10
        movq	[%r9+192], r11
        movq	[%r9+200], r12
        movq	r10, r14
        movq	r11, r14
        ; A[22] x A[4]
        mulxq	rcx, rax, [%r8+32]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[22] x A[5]
        mulxq	rcx, rax, [%r8+40]
        adcxq	r10, rax
        adoxq	r11, rcx
        movq	[%r9+208], r13
        movq	[%r9+216], r10
        ;  Carry
        adcxq	r11, r15
        movq	r15, r14
        adcxq	r15, r14
        adoxq	r15, r14
        movq	[%r9+224], r11
        ; Diagonal 4
        movq	r11, [%rbp+56]
        movq	r12, [%rbp+64]
        movq	r13, [%rbp+72]
        movq	r10, [%rbp+80]
        ; A[4] x A[3]
        movq	rdx, [%r8+24]
        mulxq	rcx, rax, [%r8+32]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[5] x A[3]
        mulxq	rcx, rax, [%r8+40]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[6] x A[3]
        mulxq	rcx, rax, [%r8+48]
        adcxq	r13, rax
        adoxq	r10, rcx
        movq	[%rbp+56], r11
        movq	[%rbp+64], r12
        movq	[%rbp+72], r13
        movq	r11, [%rbp+88]
        movq	r12, [%rbp+96]
        movq	r13, [%rbp+104]
        ; A[7] x A[3]
        mulxq	rcx, rax, [%r8+56]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[8] x A[3]
        mulxq	rcx, rax, [%r8+64]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[9] x A[3]
        mulxq	rcx, rax, [%r8+72]
        adcxq	r12, rax
        adoxq	r13, rcx
        movq	[%rbp+80], r10
        movq	[%rbp+88], r11
        movq	[%rbp+96], r12
        movq	r10, [%rbp+112]
        movq	r11, [%rbp+120]
        movq	r12, [%rbp+128]
        ; A[10] x A[3]
        mulxq	rcx, rax, [%r8+80]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[11] x A[3]
        mulxq	rcx, rax, [%r8+88]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[12] x A[3]
        mulxq	rcx, rax, [%r8+96]
        adcxq	r11, rax
        adoxq	r12, rcx
        movq	[%rbp+104], r13
        movq	[%rbp+112], r10
        movq	[%rbp+120], r11
        movq	r13, [%rbp+136]
        movq	r10, [%rbp+144]
        movq	r11, [%rbp+152]
        ; A[13] x A[3]
        mulxq	rcx, rax, [%r8+104]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[14] x A[3]
        mulxq	rcx, rax, [%r8+112]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[15] x A[3]
        mulxq	rcx, rax, [%r8+120]
        adcxq	r10, rax
        adoxq	r11, rcx
        movq	[%rbp+128], r12
        movq	[%rbp+136], r13
        movq	[%rbp+144], r10
        movq	r12, [%rbp+160]
        movq	r13, [%rbp+168]
        movq	r10, [%rbp+176]
        ; A[16] x A[3]
        mulxq	rcx, rax, [%r8+128]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[17] x A[3]
        mulxq	rcx, rax, [%r8+136]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[18] x A[3]
        mulxq	rcx, rax, [%r8+144]
        adcxq	r13, rax
        adoxq	r10, rcx
        movq	[%rbp+152], r11
        movq	[%rbp+160], r12
        movq	[%rbp+168], r13
        movq	r11, [%rbp+184]
        movq	r12, [%r9+192]
        movq	r13, [%r9+200]
        ; A[19] x A[3]
        mulxq	rcx, rax, [%r8+152]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[20] x A[3]
        mulxq	rcx, rax, [%r8+160]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[21] x A[3]
        mulxq	rcx, rax, [%r8+168]
        adcxq	r12, rax
        adoxq	r13, rcx
        movq	[%rbp+176], r10
        movq	[%rbp+184], r11
        movq	[%r9+192], r12
        movq	r10, [%r9+208]
        movq	r11, [%r9+216]
        movq	r12, [%r9+224]
        ; A[21] x A[4]
        movq	rdx, [%r8+168]
        mulxq	rcx, rax, [%r8+32]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[21] x A[5]
        mulxq	rcx, rax, [%r8+40]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[21] x A[6]
        mulxq	rcx, rax, [%r8+48]
        adcxq	r11, rax
        adoxq	r12, rcx
        movq	[%r9+200], r13
        movq	[%r9+208], r10
        movq	[%r9+216], r11
        movq	r13, r14
        movq	r10, r14
        ; A[21] x A[7]
        mulxq	rcx, rax, [%r8+56]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[21] x A[8]
        mulxq	rcx, rax, [%r8+64]
        adcxq	r13, rax
        adoxq	r10, rcx
        movq	[%r9+224], r12
        movq	[%r9+232], r13
        ;  Carry
        adcxq	r10, r15
        movq	r15, r14
        adcxq	r15, r14
        adoxq	r15, r14
        movq	[%r9+240], r10
        ; Diagonal 5
        movq	r10, [%rbp+72]
        movq	r11, [%rbp+80]
        movq	r12, [%rbp+88]
        movq	r13, [%rbp+96]
        ; A[5] x A[4]
        movq	rdx, [%r8+32]
        mulxq	rcx, rax, [%r8+40]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[6] x A[4]
        mulxq	rcx, rax, [%r8+48]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[7] x A[4]
        mulxq	rcx, rax, [%r8+56]
        adcxq	r12, rax
        adoxq	r13, rcx
        movq	[%rbp+72], r10
        movq	[%rbp+80], r11
        movq	[%rbp+88], r12
        movq	r10, [%rbp+104]
        movq	r11, [%rbp+112]
        movq	r12, [%rbp+120]
        ; A[8] x A[4]
        mulxq	rcx, rax, [%r8+64]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[9] x A[4]
        mulxq	rcx, rax, [%r8+72]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[10] x A[4]
        mulxq	rcx, rax, [%r8+80]
        adcxq	r11, rax
        adoxq	r12, rcx
        movq	[%rbp+96], r13
        movq	[%rbp+104], r10
        movq	[%rbp+112], r11
        movq	r13, [%rbp+128]
        movq	r10, [%rbp+136]
        movq	r11, [%rbp+144]
        ; A[11] x A[4]
        mulxq	rcx, rax, [%r8+88]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[12] x A[4]
        mulxq	rcx, rax, [%r8+96]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[13] x A[4]
        mulxq	rcx, rax, [%r8+104]
        adcxq	r10, rax
        adoxq	r11, rcx
        movq	[%rbp+120], r12
        movq	[%rbp+128], r13
        movq	[%rbp+136], r10
        movq	r12, [%rbp+152]
        movq	r13, [%rbp+160]
        movq	r10, [%rbp+168]
        ; A[14] x A[4]
        mulxq	rcx, rax, [%r8+112]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[15] x A[4]
        mulxq	rcx, rax, [%r8+120]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[16] x A[4]
        mulxq	rcx, rax, [%r8+128]
        adcxq	r13, rax
        adoxq	r10, rcx
        movq	[%rbp+144], r11
        movq	[%rbp+152], r12
        movq	[%rbp+160], r13
        movq	r11, [%rbp+176]
        movq	r12, [%rbp+184]
        movq	r13, [%r9+192]
        ; A[17] x A[4]
        mulxq	rcx, rax, [%r8+136]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[18] x A[4]
        mulxq	rcx, rax, [%r8+144]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[19] x A[4]
        mulxq	rcx, rax, [%r8+152]
        adcxq	r12, rax
        adoxq	r13, rcx
        movq	[%rbp+168], r10
        movq	[%rbp+176], r11
        movq	[%rbp+184], r12
        movq	r10, [%r9+200]
        movq	r11, [%r9+208]
        movq	r12, [%r9+216]
        ; A[20] x A[4]
        mulxq	rcx, rax, [%r8+160]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[20] x A[5]
        movq	rdx, [%r8+160]
        mulxq	rcx, rax, [%r8+40]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[20] x A[6]
        mulxq	rcx, rax, [%r8+48]
        adcxq	r11, rax
        adoxq	r12, rcx
        movq	[%r9+192], r13
        movq	[%r9+200], r10
        movq	[%r9+208], r11
        movq	r13, [%r9+224]
        movq	r10, [%r9+232]
        movq	r11, [%r9+240]
        ; A[20] x A[7]
        mulxq	rcx, rax, [%r8+56]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[20] x A[8]
        mulxq	rcx, rax, [%r8+64]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[20] x A[9]
        mulxq	rcx, rax, [%r8+72]
        adcxq	r10, rax
        adoxq	r11, rcx
        movq	[%r9+216], r12
        movq	[%r9+224], r13
        movq	[%r9+232], r10
        movq	r12, r14
        movq	r13, r14
        ; A[20] x A[10]
        mulxq	rcx, rax, [%r8+80]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[20] x A[11]
        mulxq	rcx, rax, [%r8+88]
        adcxq	r12, rax
        adoxq	r13, rcx
        movq	[%r9+240], r11
        movq	[%r9+248], r12
        ;  Carry
        adcxq	r13, r15
        movq	r15, r14
        adcxq	r15, r14
        adoxq	r15, r14
        movq	[%r9+256], r13
        ; Diagonal 6
        movq	r13, [%rbp+88]
        movq	r10, [%rbp+96]
        movq	r11, [%rbp+104]
        movq	r12, [%rbp+112]
        ; A[6] x A[5]
        movq	rdx, [%r8+40]
        mulxq	rcx, rax, [%r8+48]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[7] x A[5]
        mulxq	rcx, rax, [%r8+56]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[8] x A[5]
        mulxq	rcx, rax, [%r8+64]
        adcxq	r11, rax
        adoxq	r12, rcx
        movq	[%rbp+88], r13
        movq	[%rbp+96], r10
        movq	[%rbp+104], r11
        movq	r13, [%rbp+120]
        movq	r10, [%rbp+128]
        movq	r11, [%rbp+136]
        ; A[9] x A[5]
        mulxq	rcx, rax, [%r8+72]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[10] x A[5]
        mulxq	rcx, rax, [%r8+80]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[11] x A[5]
        mulxq	rcx, rax, [%r8+88]
        adcxq	r10, rax
        adoxq	r11, rcx
        movq	[%rbp+112], r12
        movq	[%rbp+120], r13
        movq	[%rbp+128], r10
        movq	r12, [%rbp+144]
        movq	r13, [%rbp+152]
        movq	r10, [%rbp+160]
        ; A[12] x A[5]
        mulxq	rcx, rax, [%r8+96]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[13] x A[5]
        mulxq	rcx, rax, [%r8+104]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[14] x A[5]
        mulxq	rcx, rax, [%r8+112]
        adcxq	r13, rax
        adoxq	r10, rcx
        movq	[%rbp+136], r11
        movq	[%rbp+144], r12
        movq	[%rbp+152], r13
        movq	r11, [%rbp+168]
        movq	r12, [%rbp+176]
        movq	r13, [%rbp+184]
        ; A[15] x A[5]
        mulxq	rcx, rax, [%r8+120]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[16] x A[5]
        mulxq	rcx, rax, [%r8+128]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[17] x A[5]
        mulxq	rcx, rax, [%r8+136]
        adcxq	r12, rax
        adoxq	r13, rcx
        movq	[%rbp+160], r10
        movq	[%rbp+168], r11
        movq	[%rbp+176], r12
        movq	r10, [%r9+192]
        movq	r11, [%r9+200]
        movq	r12, [%r9+208]
        ; A[18] x A[5]
        mulxq	rcx, rax, [%r8+144]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[19] x A[5]
        mulxq	rcx, rax, [%r8+152]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[19] x A[6]
        movq	rdx, [%r8+152]
        mulxq	rcx, rax, [%r8+48]
        adcxq	r11, rax
        adoxq	r12, rcx
        movq	[%rbp+184], r13
        movq	[%r9+192], r10
        movq	[%r9+200], r11
        movq	r13, [%r9+216]
        movq	r10, [%r9+224]
        movq	r11, [%r9+232]
        ; A[19] x A[7]
        mulxq	rcx, rax, [%r8+56]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[19] x A[8]
        mulxq	rcx, rax, [%r8+64]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[19] x A[9]
        mulxq	rcx, rax, [%r8+72]
        adcxq	r10, rax
        adoxq	r11, rcx
        movq	[%r9+208], r12
        movq	[%r9+216], r13
        movq	[%r9+224], r10
        movq	r12, [%r9+240]
        movq	r13, [%r9+248]
        movq	r10, [%r9+256]
        ; A[19] x A[10]
        mulxq	rcx, rax, [%r8+80]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[19] x A[11]
        mulxq	rcx, rax, [%r8+88]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[19] x A[12]
        mulxq	rcx, rax, [%r8+96]
        adcxq	r13, rax
        adoxq	r10, rcx
        movq	[%r9+232], r11
        movq	[%r9+240], r12
        movq	[%r9+248], r13
        movq	r11, r14
        movq	r12, r14
        ; A[19] x A[13]
        mulxq	rcx, rax, [%r8+104]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[19] x A[14]
        mulxq	rcx, rax, [%r8+112]
        adcxq	r11, rax
        adoxq	r12, rcx
        movq	[%r9+256], r10
        movq	[%r9+264], r11
        ;  Carry
        adcxq	r12, r15
        movq	r15, r14
        adcxq	r15, r14
        adoxq	r15, r14
        movq	[%r9+272], r12
        ; Diagonal 7
        movq	r12, [%rbp+104]
        movq	r13, [%rbp+112]
        movq	r10, [%rbp+120]
        movq	r11, [%rbp+128]
        ; A[7] x A[6]
        movq	rdx, [%r8+48]
        mulxq	rcx, rax, [%r8+56]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[8] x A[6]
        mulxq	rcx, rax, [%r8+64]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[9] x A[6]
        mulxq	rcx, rax, [%r8+72]
        adcxq	r10, rax
        adoxq	r11, rcx
        movq	[%rbp+104], r12
        movq	[%rbp+112], r13
        movq	[%rbp+120], r10
        movq	r12, [%rbp+136]
        movq	r13, [%rbp+144]
        movq	r10, [%rbp+152]
        ; A[10] x A[6]
        mulxq	rcx, rax, [%r8+80]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[11] x A[6]
        mulxq	rcx, rax, [%r8+88]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[12] x A[6]
        mulxq	rcx, rax, [%r8+96]
        adcxq	r13, rax
        adoxq	r10, rcx
        movq	[%rbp+128], r11
        movq	[%rbp+136], r12
        movq	[%rbp+144], r13
        movq	r11, [%rbp+160]
        movq	r12, [%rbp+168]
        movq	r13, [%rbp+176]
        ; A[13] x A[6]
        mulxq	rcx, rax, [%r8+104]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[14] x A[6]
        mulxq	rcx, rax, [%r8+112]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[15] x A[6]
        mulxq	rcx, rax, [%r8+120]
        adcxq	r12, rax
        adoxq	r13, rcx
        movq	[%rbp+152], r10
        movq	[%rbp+160], r11
        movq	[%rbp+168], r12
        movq	r10, [%rbp+184]
        movq	r11, [%r9+192]
        movq	r12, [%r9+200]
        ; A[16] x A[6]
        mulxq	rcx, rax, [%r8+128]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[17] x A[6]
        mulxq	rcx, rax, [%r8+136]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[18] x A[6]
        mulxq	rcx, rax, [%r8+144]
        adcxq	r11, rax
        adoxq	r12, rcx
        movq	[%rbp+176], r13
        movq	[%rbp+184], r10
        movq	[%r9+192], r11
        movq	r13, [%r9+208]
        movq	r10, [%r9+216]
        movq	r11, [%r9+224]
        ; A[18] x A[7]
        movq	rdx, [%r8+144]
        mulxq	rcx, rax, [%r8+56]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[18] x A[8]
        mulxq	rcx, rax, [%r8+64]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[18] x A[9]
        mulxq	rcx, rax, [%r8+72]
        adcxq	r10, rax
        adoxq	r11, rcx
        movq	[%r9+200], r12
        movq	[%r9+208], r13
        movq	[%r9+216], r10
        movq	r12, [%r9+232]
        movq	r13, [%r9+240]
        movq	r10, [%r9+248]
        ; A[18] x A[10]
        mulxq	rcx, rax, [%r8+80]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[18] x A[11]
        mulxq	rcx, rax, [%r8+88]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[18] x A[12]
        mulxq	rcx, rax, [%r8+96]
        adcxq	r13, rax
        adoxq	r10, rcx
        movq	[%r9+224], r11
        movq	[%r9+232], r12
        movq	[%r9+240], r13
        movq	r11, [%r9+256]
        movq	r12, [%r9+264]
        movq	r13, [%r9+272]
        ; A[18] x A[13]
        mulxq	rcx, rax, [%r8+104]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[18] x A[14]
        mulxq	rcx, rax, [%r8+112]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[18] x A[15]
        mulxq	rcx, rax, [%r8+120]
        adcxq	r12, rax
        adoxq	r13, rcx
        movq	[%r9+248], r10
        movq	[%r9+256], r11
        movq	[%r9+264], r12
        movq	r10, r14
        movq	r11, r14
        ; A[18] x A[16]
        mulxq	rcx, rax, [%r8+128]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[18] x A[17]
        mulxq	rcx, rax, [%r8+136]
        adcxq	r10, rax
        adoxq	r11, rcx
        movq	[%r9+272], r13
        movq	[%r9+280], r10
        ;  Carry
        adcxq	r11, r15
        movq	r15, r14
        adcxq	r15, r14
        adoxq	r15, r14
        movq	[%r9+288], r11
        ; Diagonal 8
        movq	r11, [%rbp+120]
        movq	r12, [%rbp+128]
        movq	r13, [%rbp+136]
        movq	r10, [%rbp+144]
        ; A[8] x A[7]
        movq	rdx, [%r8+56]
        mulxq	rcx, rax, [%r8+64]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[9] x A[7]
        mulxq	rcx, rax, [%r8+72]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[10] x A[7]
        mulxq	rcx, rax, [%r8+80]
        adcxq	r13, rax
        adoxq	r10, rcx
        movq	[%rbp+120], r11
        movq	[%rbp+128], r12
        movq	[%rbp+136], r13
        movq	r11, [%rbp+152]
        movq	r12, [%rbp+160]
        movq	r13, [%rbp+168]
        ; A[11] x A[7]
        mulxq	rcx, rax, [%r8+88]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[12] x A[7]
        mulxq	rcx, rax, [%r8+96]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[13] x A[7]
        mulxq	rcx, rax, [%r8+104]
        adcxq	r12, rax
        adoxq	r13, rcx
        movq	[%rbp+144], r10
        movq	[%rbp+152], r11
        movq	[%rbp+160], r12
        movq	r10, [%rbp+176]
        movq	r11, [%rbp+184]
        movq	r12, [%r9+192]
        ; A[14] x A[7]
        mulxq	rcx, rax, [%r8+112]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[15] x A[7]
        mulxq	rcx, rax, [%r8+120]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[16] x A[7]
        mulxq	rcx, rax, [%r8+128]
        adcxq	r11, rax
        adoxq	r12, rcx
        movq	[%rbp+168], r13
        movq	[%rbp+176], r10
        movq	[%rbp+184], r11
        movq	r13, [%r9+200]
        movq	r10, [%r9+208]
        movq	r11, [%r9+216]
        ; A[17] x A[7]
        mulxq	rcx, rax, [%r8+136]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[17] x A[8]
        movq	rdx, [%r8+136]
        mulxq	rcx, rax, [%r8+64]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[17] x A[9]
        mulxq	rcx, rax, [%r8+72]
        adcxq	r10, rax
        adoxq	r11, rcx
        movq	[%r9+192], r12
        movq	[%r9+200], r13
        movq	[%r9+208], r10
        movq	r12, [%r9+224]
        movq	r13, [%r9+232]
        movq	r10, [%r9+240]
        ; A[17] x A[10]
        mulxq	rcx, rax, [%r8+80]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[17] x A[11]
        mulxq	rcx, rax, [%r8+88]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[17] x A[12]
        mulxq	rcx, rax, [%r8+96]
        adcxq	r13, rax
        adoxq	r10, rcx
        movq	[%r9+216], r11
        movq	[%r9+224], r12
        movq	[%r9+232], r13
        movq	r11, [%r9+248]
        movq	r12, [%r9+256]
        movq	r13, [%r9+264]
        ; A[17] x A[13]
        mulxq	rcx, rax, [%r8+104]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[17] x A[14]
        mulxq	rcx, rax, [%r8+112]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[17] x A[15]
        mulxq	rcx, rax, [%r8+120]
        adcxq	r12, rax
        adoxq	r13, rcx
        movq	[%r9+240], r10
        movq	[%r9+248], r11
        movq	[%r9+256], r12
        movq	r10, [%r9+272]
        movq	r11, [%r9+280]
        movq	r12, [%r9+288]
        ; A[17] x A[16]
        mulxq	rcx, rax, [%r8+128]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[19] x A[15]
        movq	rdx, [%r8+152]
        mulxq	rcx, rax, [%r8+120]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[19] x A[16]
        mulxq	rcx, rax, [%r8+128]
        adcxq	r11, rax
        adoxq	r12, rcx
        movq	[%r9+264], r13
        movq	[%r9+272], r10
        movq	[%r9+280], r11
        movq	r13, r14
        movq	r10, r14
        ; A[19] x A[17]
        mulxq	rcx, rax, [%r8+136]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[19] x A[18]
        mulxq	rcx, rax, [%r8+144]
        adcxq	r13, rax
        adoxq	r10, rcx
        movq	[%r9+288], r12
        movq	[%r9+296], r13
        ;  Carry
        adcxq	r10, r15
        movq	r15, r14
        adcxq	r15, r14
        adoxq	r15, r14
        movq	[%r9+304], r10
        ; Diagonal 9
        movq	r10, [%rbp+136]
        movq	r11, [%rbp+144]
        movq	r12, [%rbp+152]
        movq	r13, [%rbp+160]
        ; A[9] x A[8]
        movq	rdx, [%r8+64]
        mulxq	rcx, rax, [%r8+72]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[10] x A[8]
        mulxq	rcx, rax, [%r8+80]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[11] x A[8]
        mulxq	rcx, rax, [%r8+88]
        adcxq	r12, rax
        adoxq	r13, rcx
        movq	[%rbp+136], r10
        movq	[%rbp+144], r11
        movq	[%rbp+152], r12
        movq	r10, [%rbp+168]
        movq	r11, [%rbp+176]
        movq	r12, [%rbp+184]
        ; A[12] x A[8]
        mulxq	rcx, rax, [%r8+96]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[13] x A[8]
        mulxq	rcx, rax, [%r8+104]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[14] x A[8]
        mulxq	rcx, rax, [%r8+112]
        adcxq	r11, rax
        adoxq	r12, rcx
        movq	[%rbp+160], r13
        movq	[%rbp+168], r10
        movq	[%rbp+176], r11
        movq	r13, [%r9+192]
        movq	r10, [%r9+200]
        movq	r11, [%r9+208]
        ; A[15] x A[8]
        mulxq	rcx, rax, [%r8+120]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[16] x A[8]
        mulxq	rcx, rax, [%r8+128]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[16] x A[9]
        movq	rdx, [%r8+128]
        mulxq	rcx, rax, [%r8+72]
        adcxq	r10, rax
        adoxq	r11, rcx
        movq	[%rbp+184], r12
        movq	[%r9+192], r13
        movq	[%r9+200], r10
        movq	r12, [%r9+216]
        movq	r13, [%r9+224]
        movq	r10, [%r9+232]
        ; A[16] x A[10]
        mulxq	rcx, rax, [%r8+80]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[16] x A[11]
        mulxq	rcx, rax, [%r8+88]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[16] x A[12]
        mulxq	rcx, rax, [%r8+96]
        adcxq	r13, rax
        adoxq	r10, rcx
        movq	[%r9+208], r11
        movq	[%r9+216], r12
        movq	[%r9+224], r13
        movq	r11, [%r9+240]
        movq	r12, [%r9+248]
        movq	r13, [%r9+256]
        ; A[16] x A[13]
        mulxq	rcx, rax, [%r8+104]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[16] x A[14]
        mulxq	rcx, rax, [%r8+112]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[16] x A[15]
        mulxq	rcx, rax, [%r8+120]
        adcxq	r12, rax
        adoxq	r13, rcx
        movq	[%r9+232], r10
        movq	[%r9+240], r11
        movq	[%r9+248], r12
        movq	r10, [%r9+264]
        movq	r11, [%r9+272]
        movq	r12, [%r9+280]
        ; A[20] x A[12]
        movq	rdx, [%r8+160]
        mulxq	rcx, rax, [%r8+96]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[20] x A[13]
        mulxq	rcx, rax, [%r8+104]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[20] x A[14]
        mulxq	rcx, rax, [%r8+112]
        adcxq	r11, rax
        adoxq	r12, rcx
        movq	[%r9+256], r13
        movq	[%r9+264], r10
        movq	[%r9+272], r11
        movq	r13, [%r9+288]
        movq	r10, [%r9+296]
        movq	r11, [%r9+304]
        ; A[20] x A[15]
        mulxq	rcx, rax, [%r8+120]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[20] x A[16]
        mulxq	rcx, rax, [%r8+128]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[20] x A[17]
        mulxq	rcx, rax, [%r8+136]
        adcxq	r10, rax
        adoxq	r11, rcx
        movq	[%r9+280], r12
        movq	[%r9+288], r13
        movq	[%r9+296], r10
        movq	r12, r14
        movq	r13, r14
        ; A[20] x A[18]
        mulxq	rcx, rax, [%r8+144]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[20] x A[19]
        mulxq	rcx, rax, [%r8+152]
        adcxq	r12, rax
        adoxq	r13, rcx
        movq	[%r9+304], r11
        movq	[%r9+312], r12
        ;  Carry
        adcxq	r13, r15
        movq	r15, r14
        adcxq	r15, r14
        adoxq	r15, r14
        movq	[%r9+320], r13
        ; Diagonal 10
        movq	r13, [%rbp+152]
        movq	r10, [%rbp+160]
        movq	r11, [%rbp+168]
        movq	r12, [%rbp+176]
        ; A[10] x A[9]
        movq	rdx, [%r8+72]
        mulxq	rcx, rax, [%r8+80]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[11] x A[9]
        mulxq	rcx, rax, [%r8+88]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[12] x A[9]
        mulxq	rcx, rax, [%r8+96]
        adcxq	r11, rax
        adoxq	r12, rcx
        movq	[%rbp+152], r13
        movq	[%rbp+160], r10
        movq	[%rbp+168], r11
        movq	r13, [%rbp+184]
        movq	r10, [%r9+192]
        movq	r11, [%r9+200]
        ; A[13] x A[9]
        mulxq	rcx, rax, [%r8+104]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[14] x A[9]
        mulxq	rcx, rax, [%r8+112]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[15] x A[9]
        mulxq	rcx, rax, [%r8+120]
        adcxq	r10, rax
        adoxq	r11, rcx
        movq	[%rbp+176], r12
        movq	[%rbp+184], r13
        movq	[%r9+192], r10
        movq	r12, [%r9+208]
        movq	r13, [%r9+216]
        movq	r10, [%r9+224]
        ; A[15] x A[10]
        movq	rdx, [%r8+120]
        mulxq	rcx, rax, [%r8+80]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[15] x A[11]
        mulxq	rcx, rax, [%r8+88]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[15] x A[12]
        mulxq	rcx, rax, [%r8+96]
        adcxq	r13, rax
        adoxq	r10, rcx
        movq	[%r9+200], r11
        movq	[%r9+208], r12
        movq	[%r9+216], r13
        movq	r11, [%r9+232]
        movq	r12, [%r9+240]
        movq	r13, [%r9+248]
        ; A[15] x A[13]
        mulxq	rcx, rax, [%r8+104]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[15] x A[14]
        mulxq	rcx, rax, [%r8+112]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[21] x A[9]
        movq	rdx, [%r8+168]
        mulxq	rcx, rax, [%r8+72]
        adcxq	r12, rax
        adoxq	r13, rcx
        movq	[%r9+224], r10
        movq	[%r9+232], r11
        movq	[%r9+240], r12
        movq	r10, [%r9+256]
        movq	r11, [%r9+264]
        movq	r12, [%r9+272]
        ; A[21] x A[10]
        mulxq	rcx, rax, [%r8+80]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[21] x A[11]
        mulxq	rcx, rax, [%r8+88]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[21] x A[12]
        mulxq	rcx, rax, [%r8+96]
        adcxq	r11, rax
        adoxq	r12, rcx
        movq	[%r9+248], r13
        movq	[%r9+256], r10
        movq	[%r9+264], r11
        movq	r13, [%r9+280]
        movq	r10, [%r9+288]
        movq	r11, [%r9+296]
        ; A[21] x A[13]
        mulxq	rcx, rax, [%r8+104]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[21] x A[14]
        mulxq	rcx, rax, [%r8+112]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[21] x A[15]
        mulxq	rcx, rax, [%r8+120]
        adcxq	r10, rax
        adoxq	r11, rcx
        movq	[%r9+272], r12
        movq	[%r9+280], r13
        movq	[%r9+288], r10
        movq	r12, [%r9+304]
        movq	r13, [%r9+312]
        movq	r10, [%r9+320]
        ; A[21] x A[16]
        mulxq	rcx, rax, [%r8+128]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[21] x A[17]
        mulxq	rcx, rax, [%r8+136]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[21] x A[18]
        mulxq	rcx, rax, [%r8+144]
        adcxq	r13, rax
        adoxq	r10, rcx
        movq	[%r9+296], r11
        movq	[%r9+304], r12
        movq	[%r9+312], r13
        movq	r11, r14
        movq	r12, r14
        ; A[21] x A[19]
        mulxq	rcx, rax, [%r8+152]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[21] x A[20]
        mulxq	rcx, rax, [%r8+160]
        adcxq	r11, rax
        adoxq	r12, rcx
        movq	[%r9+320], r10
        movq	[%r9+328], r11
        ;  Carry
        adcxq	r12, r15
        movq	r15, r14
        adcxq	r15, r14
        adoxq	r15, r14
        movq	[%r9+336], r12
        ; Diagonal 11
        movq	r12, [%rbp+168]
        movq	r13, [%rbp+176]
        movq	r10, [%rbp+184]
        movq	r11, [%r9+192]
        ; A[11] x A[10]
        movq	rdx, [%r8+80]
        mulxq	rcx, rax, [%r8+88]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[12] x A[10]
        mulxq	rcx, rax, [%r8+96]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[13] x A[10]
        mulxq	rcx, rax, [%r8+104]
        adcxq	r10, rax
        adoxq	r11, rcx
        movq	[%rbp+168], r12
        movq	[%rbp+176], r13
        movq	[%rbp+184], r10
        movq	r12, [%r9+200]
        movq	r13, [%r9+208]
        movq	r10, [%r9+216]
        ; A[14] x A[10]
        mulxq	rcx, rax, [%r8+112]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[14] x A[11]
        movq	rdx, [%r8+112]
        mulxq	rcx, rax, [%r8+88]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[14] x A[12]
        mulxq	rcx, rax, [%r8+96]
        adcxq	r13, rax
        adoxq	r10, rcx
        movq	[%r9+192], r11
        movq	[%r9+200], r12
        movq	[%r9+208], r13
        movq	r11, [%r9+224]
        movq	r12, [%r9+232]
        movq	r13, [%r9+240]
        ; A[14] x A[13]
        mulxq	rcx, rax, [%r8+104]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[22] x A[6]
        movq	rdx, [%r8+176]
        mulxq	rcx, rax, [%r8+48]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[22] x A[7]
        mulxq	rcx, rax, [%r8+56]
        adcxq	r12, rax
        adoxq	r13, rcx
        movq	[%r9+216], r10
        movq	[%r9+224], r11
        movq	[%r9+232], r12
        movq	r10, [%r9+248]
        movq	r11, [%r9+256]
        movq	r12, [%r9+264]
        ; A[22] x A[8]
        mulxq	rcx, rax, [%r8+64]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[22] x A[9]
        mulxq	rcx, rax, [%r8+72]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[22] x A[10]
        mulxq	rcx, rax, [%r8+80]
        adcxq	r11, rax
        adoxq	r12, rcx
        movq	[%r9+240], r13
        movq	[%r9+248], r10
        movq	[%r9+256], r11
        movq	r13, [%r9+272]
        movq	r10, [%r9+280]
        movq	r11, [%r9+288]
        ; A[22] x A[11]
        mulxq	rcx, rax, [%r8+88]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[22] x A[12]
        mulxq	rcx, rax, [%r8+96]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[22] x A[13]
        mulxq	rcx, rax, [%r8+104]
        adcxq	r10, rax
        adoxq	r11, rcx
        movq	[%r9+264], r12
        movq	[%r9+272], r13
        movq	[%r9+280], r10
        movq	r12, [%r9+296]
        movq	r13, [%r9+304]
        movq	r10, [%r9+312]
        ; A[22] x A[14]
        mulxq	rcx, rax, [%r8+112]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[22] x A[15]
        mulxq	rcx, rax, [%r8+120]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[22] x A[16]
        mulxq	rcx, rax, [%r8+128]
        adcxq	r13, rax
        adoxq	r10, rcx
        movq	[%r9+288], r11
        movq	[%r9+296], r12
        movq	[%r9+304], r13
        movq	r11, [%r9+320]
        movq	r12, [%r9+328]
        movq	r13, [%r9+336]
        ; A[22] x A[17]
        mulxq	rcx, rax, [%r8+136]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[22] x A[18]
        mulxq	rcx, rax, [%r8+144]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[22] x A[19]
        mulxq	rcx, rax, [%r8+152]
        adcxq	r12, rax
        adoxq	r13, rcx
        movq	[%r9+312], r10
        movq	[%r9+320], r11
        movq	[%r9+328], r12
        movq	r10, r14
        movq	r11, r14
        ; A[22] x A[20]
        mulxq	rcx, rax, [%r8+160]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[22] x A[21]
        mulxq	rcx, rax, [%r8+168]
        adcxq	r10, rax
        adoxq	r11, rcx
        movq	[%r9+336], r13
        movq	[%r9+344], r10
        ;  Carry
        adcxq	r11, r15
        movq	r15, r14
        adcxq	r15, r14
        adoxq	r15, r14
        movq	[%r9+352], r11
        ; Diagonal 12
        movq	r11, [%rbp+184]
        movq	r12, [%r9+192]
        movq	r13, [%r9+200]
        movq	r10, [%r9+208]
        ; A[12] x A[11]
        movq	rdx, [%r8+88]
        mulxq	rcx, rax, [%r8+96]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[13] x A[11]
        mulxq	rcx, rax, [%r8+104]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[13] x A[12]
        movq	rdx, [%r8+96]
        mulxq	rcx, rax, [%r8+104]
        adcxq	r13, rax
        adoxq	r10, rcx
        movq	[%rbp+184], r11
        movq	[%r9+192], r12
        movq	[%r9+200], r13
        movq	r11, [%r9+216]
        movq	r12, [%r9+224]
        movq	r13, [%r9+232]
        ; A[23] x A[3]
        movq	rdx, [%r8+184]
        mulxq	rcx, rax, [%r8+24]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[23] x A[4]
        mulxq	rcx, rax, [%r8+32]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[23] x A[5]
        mulxq	rcx, rax, [%r8+40]
        adcxq	r12, rax
        adoxq	r13, rcx
        movq	[%r9+208], r10
        movq	[%r9+216], r11
        movq	[%r9+224], r12
        movq	r10, [%r9+240]
        movq	r11, [%r9+248]
        movq	r12, [%r9+256]
        ; A[23] x A[6]
        mulxq	rcx, rax, [%r8+48]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[23] x A[7]
        mulxq	rcx, rax, [%r8+56]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[23] x A[8]
        mulxq	rcx, rax, [%r8+64]
        adcxq	r11, rax
        adoxq	r12, rcx
        movq	[%r9+232], r13
        movq	[%r9+240], r10
        movq	[%r9+248], r11
        movq	r13, [%r9+264]
        movq	r10, [%r9+272]
        movq	r11, [%r9+280]
        ; A[23] x A[9]
        mulxq	rcx, rax, [%r8+72]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[23] x A[10]
        mulxq	rcx, rax, [%r8+80]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[23] x A[11]
        mulxq	rcx, rax, [%r8+88]
        adcxq	r10, rax
        adoxq	r11, rcx
        movq	[%r9+256], r12
        movq	[%r9+264], r13
        movq	[%r9+272], r10
        movq	r12, [%r9+288]
        movq	r13, [%r9+296]
        movq	r10, [%r9+304]
        ; A[23] x A[12]
        mulxq	rcx, rax, [%r8+96]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[23] x A[13]
        mulxq	rcx, rax, [%r8+104]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[23] x A[14]
        mulxq	rcx, rax, [%r8+112]
        adcxq	r13, rax
        adoxq	r10, rcx
        movq	[%r9+280], r11
        movq	[%r9+288], r12
        movq	[%r9+296], r13
        movq	r11, [%r9+312]
        movq	r12, [%r9+320]
        movq	r13, [%r9+328]
        ; A[23] x A[15]
        mulxq	rcx, rax, [%r8+120]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[23] x A[16]
        mulxq	rcx, rax, [%r8+128]
        adcxq	r11, rax
        adoxq	r12, rcx
        ; A[23] x A[17]
        mulxq	rcx, rax, [%r8+136]
        adcxq	r12, rax
        adoxq	r13, rcx
        movq	[%r9+304], r10
        movq	[%r9+312], r11
        movq	[%r9+320], r12
        movq	r10, [%r9+336]
        movq	r11, [%r9+344]
        movq	r12, [%r9+352]
        ; A[23] x A[18]
        mulxq	rcx, rax, [%r8+144]
        adcxq	r13, rax
        adoxq	r10, rcx
        ; A[23] x A[19]
        mulxq	rcx, rax, [%r8+152]
        adcxq	r10, rax
        adoxq	r11, rcx
        ; A[23] x A[20]
        mulxq	rcx, rax, [%r8+160]
        adcxq	r11, rax
        adoxq	r12, rcx
        movq	[%r9+328], r13
        movq	[%r9+336], r10
        movq	[%r9+344], r11
        movq	r13, r14
        movq	r10, r14
        ; A[23] x A[21]
        mulxq	rcx, rax, [%r8+168]
        adcxq	r12, rax
        adoxq	r13, rcx
        ; A[23] x A[22]
        mulxq	rcx, rax, [%r8+176]
        adcxq	r13, rax
        adoxq	r10, rcx
        movq	[%r9+352], r12
        movq	[%r9+360], r13
        ;  Carry
        adcxq	r10, r15
        movq	r15, r14
        adcxq	r15, r14
        adoxq	r15, r14
        movq	[%r9+368], r10
        movq	[%r9+376], r15
        ; Double and Add in A[i] x A[i]
        movq	r11, [%rbp+8]
        ; A[0] x A[0]
        movq	rdx, [%r8]
        mulxq	rcx, rax, rdx
        movq	[%rbp], rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%rbp+8], r11
        movq	r10, [%rbp+16]
        movq	r11, [%rbp+24]
        ; A[1] x A[1]
        movq	rdx, [%r8+8]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%rbp+16], r10
        movq	[%rbp+24], r11
        movq	r10, [%rbp+32]
        movq	r11, [%rbp+40]
        ; A[2] x A[2]
        movq	rdx, [%r8+16]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%rbp+32], r10
        movq	[%rbp+40], r11
        movq	r10, [%rbp+48]
        movq	r11, [%rbp+56]
        ; A[3] x A[3]
        movq	rdx, [%r8+24]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%rbp+48], r10
        movq	[%rbp+56], r11
        movq	r10, [%rbp+64]
        movq	r11, [%rbp+72]
        ; A[4] x A[4]
        movq	rdx, [%r8+32]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%rbp+64], r10
        movq	[%rbp+72], r11
        movq	r10, [%rbp+80]
        movq	r11, [%rbp+88]
        ; A[5] x A[5]
        movq	rdx, [%r8+40]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%rbp+80], r10
        movq	[%rbp+88], r11
        movq	r10, [%rbp+96]
        movq	r11, [%rbp+104]
        ; A[6] x A[6]
        movq	rdx, [%r8+48]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%rbp+96], r10
        movq	[%rbp+104], r11
        movq	r10, [%rbp+112]
        movq	r11, [%rbp+120]
        ; A[7] x A[7]
        movq	rdx, [%r8+56]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%rbp+112], r10
        movq	[%rbp+120], r11
        movq	r10, [%rbp+128]
        movq	r11, [%rbp+136]
        ; A[8] x A[8]
        movq	rdx, [%r8+64]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%rbp+128], r10
        movq	[%rbp+136], r11
        movq	r10, [%rbp+144]
        movq	r11, [%rbp+152]
        ; A[9] x A[9]
        movq	rdx, [%r8+72]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%rbp+144], r10
        movq	[%rbp+152], r11
        movq	r10, [%rbp+160]
        movq	r11, [%rbp+168]
        ; A[10] x A[10]
        movq	rdx, [%r8+80]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%rbp+160], r10
        movq	[%rbp+168], r11
        movq	r10, [%rbp+176]
        movq	r11, [%rbp+184]
        ; A[11] x A[11]
        movq	rdx, [%r8+88]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%rbp+176], r10
        movq	[%rbp+184], r11
        movq	r10, [%r9+192]
        movq	r11, [%r9+200]
        ; A[12] x A[12]
        movq	rdx, [%r8+96]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%r9+192], r10
        movq	[%r9+200], r11
        movq	r10, [%r9+208]
        movq	r11, [%r9+216]
        ; A[13] x A[13]
        movq	rdx, [%r8+104]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%r9+208], r10
        movq	[%r9+216], r11
        movq	r10, [%r9+224]
        movq	r11, [%r9+232]
        ; A[14] x A[14]
        movq	rdx, [%r8+112]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%r9+224], r10
        movq	[%r9+232], r11
        movq	r10, [%r9+240]
        movq	r11, [%r9+248]
        ; A[15] x A[15]
        movq	rdx, [%r8+120]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%r9+240], r10
        movq	[%r9+248], r11
        movq	r10, [%r9+256]
        movq	r11, [%r9+264]
        ; A[16] x A[16]
        movq	rdx, [%r8+128]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%r9+256], r10
        movq	[%r9+264], r11
        movq	r10, [%r9+272]
        movq	r11, [%r9+280]
        ; A[17] x A[17]
        movq	rdx, [%r8+136]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%r9+272], r10
        movq	[%r9+280], r11
        movq	r10, [%r9+288]
        movq	r11, [%r9+296]
        ; A[18] x A[18]
        movq	rdx, [%r8+144]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%r9+288], r10
        movq	[%r9+296], r11
        movq	r10, [%r9+304]
        movq	r11, [%r9+312]
        ; A[19] x A[19]
        movq	rdx, [%r8+152]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%r9+304], r10
        movq	[%r9+312], r11
        movq	r10, [%r9+320]
        movq	r11, [%r9+328]
        ; A[20] x A[20]
        movq	rdx, [%r8+160]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%r9+320], r10
        movq	[%r9+328], r11
        movq	r10, [%r9+336]
        movq	r11, [%r9+344]
        ; A[21] x A[21]
        movq	rdx, [%r8+168]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%r9+336], r10
        movq	[%r9+344], r11
        movq	r10, [%r9+352]
        movq	r11, [%r9+360]
        ; A[22] x A[22]
        movq	rdx, [%r8+176]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%r9+352], r10
        movq	[%r9+360], r11
        movq	r10, [%r9+368]
        movq	r11, [%r9+376]
        ; A[23] x A[23]
        movq	rdx, [%r8+184]
        mulxq	rcx, rax, rdx
        adoxq	r10, r10
        adcxq	r10, rax
        adoxq	r11, r11
        adcxq	r11, rcx
        movq	[%r9+368], r10
        movq	[%r9+376], r11
        cmpq	r8, r9
        jne	L_end_3072_sqr_avx2_24
        movq	r10, [%rbp]
        movq	r11, [%rbp+8]
        movq	r12, [%rbp+16]
        movq	r13, [%rbp+24]
        movq	[%r9], r10
        movq	[%r9+8], r11
        movq	[%r9+16], r12
        movq	[%r9+24], r13
        movq	r10, [%rbp+32]
        movq	r11, [%rbp+40]
        movq	r12, [%rbp+48]
        movq	r13, [%rbp+56]
        movq	[%r9+32], r10
        movq	[%r9+40], r11
        movq	[%r9+48], r12
        movq	[%r9+56], r13
        movq	r10, [%rbp+64]
        movq	r11, [%rbp+72]
        movq	r12, [%rbp+80]
        movq	r13, [%rbp+88]
        movq	[%r9+64], r10
        movq	[%r9+72], r11
        movq	[%r9+80], r12
        movq	[%r9+88], r13
        movq	r10, [%rbp+96]
        movq	r11, [%rbp+104]
        movq	r12, [%rbp+112]
        movq	r13, [%rbp+120]
        movq	[%r9+96], r10
        movq	[%r9+104], r11
        movq	[%r9+112], r12
        movq	[%r9+120], r13
        movq	r10, [%rbp+128]
        movq	r11, [%rbp+136]
        movq	r12, [%rbp+144]
        movq	r13, [%rbp+152]
        movq	[%r9+128], r10
        movq	[%r9+136], r11
        movq	[%r9+144], r12
        movq	[%r9+152], r13
        movq	r10, [%rbp+160]
        movq	r11, [%rbp+168]
        movq	r12, [%rbp+176]
        movq	r13, [%rbp+184]
        movq	[%r9+160], r10
        movq	[%r9+168], r11
        movq	[%r9+176], r12
        movq	[%r9+184], r13
L_end_3072_sqr_avx2_24:
        addq	rsp, 192
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rbp
        repz retq
sp_3072_sqr_avx2_24 ENDP
ENDIF
; /* Add b to a into r. (r = a + b)
;  *
;  * r  A single precision integer.
;  * a  A single precision integer.
;  * b  A single precision integer.
;  */
sp_3072_add_24 PROC
        xorq	rax, rax
        movq	r9, [%rdx]
        addq	r9, [%r8]
        movq	[%rcx], r9
        movq	r9, [%rdx+8]
        adcq	r9, [%r8+8]
        movq	[%rcx+8], r9
        movq	r9, [%rdx+16]
        adcq	r9, [%r8+16]
        movq	[%rcx+16], r9
        movq	r9, [%rdx+24]
        adcq	r9, [%r8+24]
        movq	[%rcx+24], r9
        movq	r9, [%rdx+32]
        adcq	r9, [%r8+32]
        movq	[%rcx+32], r9
        movq	r9, [%rdx+40]
        adcq	r9, [%r8+40]
        movq	[%rcx+40], r9
        movq	r9, [%rdx+48]
        adcq	r9, [%r8+48]
        movq	[%rcx+48], r9
        movq	r9, [%rdx+56]
        adcq	r9, [%r8+56]
        movq	[%rcx+56], r9
        movq	r9, [%rdx+64]
        adcq	r9, [%r8+64]
        movq	[%rcx+64], r9
        movq	r9, [%rdx+72]
        adcq	r9, [%r8+72]
        movq	[%rcx+72], r9
        movq	r9, [%rdx+80]
        adcq	r9, [%r8+80]
        movq	[%rcx+80], r9
        movq	r9, [%rdx+88]
        adcq	r9, [%r8+88]
        movq	[%rcx+88], r9
        movq	r9, [%rdx+96]
        adcq	r9, [%r8+96]
        movq	[%rcx+96], r9
        movq	r9, [%rdx+104]
        adcq	r9, [%r8+104]
        movq	[%rcx+104], r9
        movq	r9, [%rdx+112]
        adcq	r9, [%r8+112]
        movq	[%rcx+112], r9
        movq	r9, [%rdx+120]
        adcq	r9, [%r8+120]
        movq	[%rcx+120], r9
        movq	r9, [%rdx+128]
        adcq	r9, [%r8+128]
        movq	[%rcx+128], r9
        movq	r9, [%rdx+136]
        adcq	r9, [%r8+136]
        movq	[%rcx+136], r9
        movq	r9, [%rdx+144]
        adcq	r9, [%r8+144]
        movq	[%rcx+144], r9
        movq	r9, [%rdx+152]
        adcq	r9, [%r8+152]
        movq	[%rcx+152], r9
        movq	r9, [%rdx+160]
        adcq	r9, [%r8+160]
        movq	[%rcx+160], r9
        movq	r9, [%rdx+168]
        adcq	r9, [%r8+168]
        movq	[%rcx+168], r9
        movq	r9, [%rdx+176]
        adcq	r9, [%r8+176]
        movq	[%rcx+176], r9
        movq	r9, [%rdx+184]
        adcq	r9, [%r8+184]
        movq	[%rcx+184], r9
        adcq	rax, 0
        repz retq
sp_3072_add_24 ENDP
; /* Sub b from a into a. (a -= b)
;  *
;  * a  A single precision integer and result.
;  * b  A single precision integer.
;  */
sp_3072_sub_in_place_48 PROC
        xorq	rax, rax
        movq	r8, [%rcx]
        movq	r9, [%rcx+8]
        movq	r10, [%rdx]
        movq	r11, [%rdx+8]
        subq	r8, r10
        movq	r10, [%rdx+16]
        movq	[%rcx], r8
        movq	r8, [%rcx+16]
        sbbq	r9, r11
        movq	r11, [%rdx+24]
        movq	[%rcx+8], r9
        movq	r9, [%rcx+24]
        sbbq	r8, r10
        movq	r10, [%rdx+32]
        movq	[%rcx+16], r8
        movq	r8, [%rcx+32]
        sbbq	r9, r11
        movq	r11, [%rdx+40]
        movq	[%rcx+24], r9
        movq	r9, [%rcx+40]
        sbbq	r8, r10
        movq	r10, [%rdx+48]
        movq	[%rcx+32], r8
        movq	r8, [%rcx+48]
        sbbq	r9, r11
        movq	r11, [%rdx+56]
        movq	[%rcx+40], r9
        movq	r9, [%rcx+56]
        sbbq	r8, r10
        movq	r10, [%rdx+64]
        movq	[%rcx+48], r8
        movq	r8, [%rcx+64]
        sbbq	r9, r11
        movq	r11, [%rdx+72]
        movq	[%rcx+56], r9
        movq	r9, [%rcx+72]
        sbbq	r8, r10
        movq	r10, [%rdx+80]
        movq	[%rcx+64], r8
        movq	r8, [%rcx+80]
        sbbq	r9, r11
        movq	r11, [%rdx+88]
        movq	[%rcx+72], r9
        movq	r9, [%rcx+88]
        sbbq	r8, r10
        movq	r10, [%rdx+96]
        movq	[%rcx+80], r8
        movq	r8, [%rcx+96]
        sbbq	r9, r11
        movq	r11, [%rdx+104]
        movq	[%rcx+88], r9
        movq	r9, [%rcx+104]
        sbbq	r8, r10
        movq	r10, [%rdx+112]
        movq	[%rcx+96], r8
        movq	r8, [%rcx+112]
        sbbq	r9, r11
        movq	r11, [%rdx+120]
        movq	[%rcx+104], r9
        movq	r9, [%rcx+120]
        sbbq	r8, r10
        movq	r10, [%rdx+128]
        movq	[%rcx+112], r8
        movq	r8, [%rcx+128]
        sbbq	r9, r11
        movq	r11, [%rdx+136]
        movq	[%rcx+120], r9
        movq	r9, [%rcx+136]
        sbbq	r8, r10
        movq	r10, [%rdx+144]
        movq	[%rcx+128], r8
        movq	r8, [%rcx+144]
        sbbq	r9, r11
        movq	r11, [%rdx+152]
        movq	[%rcx+136], r9
        movq	r9, [%rcx+152]
        sbbq	r8, r10
        movq	r10, [%rdx+160]
        movq	[%rcx+144], r8
        movq	r8, [%rcx+160]
        sbbq	r9, r11
        movq	r11, [%rdx+168]
        movq	[%rcx+152], r9
        movq	r9, [%rcx+168]
        sbbq	r8, r10
        movq	r10, [%rdx+176]
        movq	[%rcx+160], r8
        movq	r8, [%rcx+176]
        sbbq	r9, r11
        movq	r11, [%rdx+184]
        movq	[%rcx+168], r9
        movq	r9, [%rcx+184]
        sbbq	r8, r10
        movq	r10, [%rdx+192]
        movq	[%rcx+176], r8
        movq	r8, [%rcx+192]
        sbbq	r9, r11
        movq	r11, [%rdx+200]
        movq	[%rcx+184], r9
        movq	r9, [%rcx+200]
        sbbq	r8, r10
        movq	r10, [%rdx+208]
        movq	[%rcx+192], r8
        movq	r8, [%rcx+208]
        sbbq	r9, r11
        movq	r11, [%rdx+216]
        movq	[%rcx+200], r9
        movq	r9, [%rcx+216]
        sbbq	r8, r10
        movq	r10, [%rdx+224]
        movq	[%rcx+208], r8
        movq	r8, [%rcx+224]
        sbbq	r9, r11
        movq	r11, [%rdx+232]
        movq	[%rcx+216], r9
        movq	r9, [%rcx+232]
        sbbq	r8, r10
        movq	r10, [%rdx+240]
        movq	[%rcx+224], r8
        movq	r8, [%rcx+240]
        sbbq	r9, r11
        movq	r11, [%rdx+248]
        movq	[%rcx+232], r9
        movq	r9, [%rcx+248]
        sbbq	r8, r10
        movq	r10, [%rdx+256]
        movq	[%rcx+240], r8
        movq	r8, [%rcx+256]
        sbbq	r9, r11
        movq	r11, [%rdx+264]
        movq	[%rcx+248], r9
        movq	r9, [%rcx+264]
        sbbq	r8, r10
        movq	r10, [%rdx+272]
        movq	[%rcx+256], r8
        movq	r8, [%rcx+272]
        sbbq	r9, r11
        movq	r11, [%rdx+280]
        movq	[%rcx+264], r9
        movq	r9, [%rcx+280]
        sbbq	r8, r10
        movq	r10, [%rdx+288]
        movq	[%rcx+272], r8
        movq	r8, [%rcx+288]
        sbbq	r9, r11
        movq	r11, [%rdx+296]
        movq	[%rcx+280], r9
        movq	r9, [%rcx+296]
        sbbq	r8, r10
        movq	r10, [%rdx+304]
        movq	[%rcx+288], r8
        movq	r8, [%rcx+304]
        sbbq	r9, r11
        movq	r11, [%rdx+312]
        movq	[%rcx+296], r9
        movq	r9, [%rcx+312]
        sbbq	r8, r10
        movq	r10, [%rdx+320]
        movq	[%rcx+304], r8
        movq	r8, [%rcx+320]
        sbbq	r9, r11
        movq	r11, [%rdx+328]
        movq	[%rcx+312], r9
        movq	r9, [%rcx+328]
        sbbq	r8, r10
        movq	r10, [%rdx+336]
        movq	[%rcx+320], r8
        movq	r8, [%rcx+336]
        sbbq	r9, r11
        movq	r11, [%rdx+344]
        movq	[%rcx+328], r9
        movq	r9, [%rcx+344]
        sbbq	r8, r10
        movq	r10, [%rdx+352]
        movq	[%rcx+336], r8
        movq	r8, [%rcx+352]
        sbbq	r9, r11
        movq	r11, [%rdx+360]
        movq	[%rcx+344], r9
        movq	r9, [%rcx+360]
        sbbq	r8, r10
        movq	r10, [%rdx+368]
        movq	[%rcx+352], r8
        movq	r8, [%rcx+368]
        sbbq	r9, r11
        movq	r11, [%rdx+376]
        movq	[%rcx+360], r9
        movq	r9, [%rcx+376]
        sbbq	r8, r10
        movq	[%rcx+368], r8
        sbbq	r9, r11
        movq	[%rcx+376], r9
        sbbq	rax, 0
        repz retq
sp_3072_sub_in_place_48 ENDP
; /* Add b to a into r. (r = a + b)
;  *
;  * r  A single precision integer.
;  * a  A single precision integer.
;  * b  A single precision integer.
;  */
sp_3072_add_48 PROC
        xorq	rax, rax
        movq	r9, [%rdx]
        addq	r9, [%r8]
        movq	[%rcx], r9
        movq	r9, [%rdx+8]
        adcq	r9, [%r8+8]
        movq	[%rcx+8], r9
        movq	r9, [%rdx+16]
        adcq	r9, [%r8+16]
        movq	[%rcx+16], r9
        movq	r9, [%rdx+24]
        adcq	r9, [%r8+24]
        movq	[%rcx+24], r9
        movq	r9, [%rdx+32]
        adcq	r9, [%r8+32]
        movq	[%rcx+32], r9
        movq	r9, [%rdx+40]
        adcq	r9, [%r8+40]
        movq	[%rcx+40], r9
        movq	r9, [%rdx+48]
        adcq	r9, [%r8+48]
        movq	[%rcx+48], r9
        movq	r9, [%rdx+56]
        adcq	r9, [%r8+56]
        movq	[%rcx+56], r9
        movq	r9, [%rdx+64]
        adcq	r9, [%r8+64]
        movq	[%rcx+64], r9
        movq	r9, [%rdx+72]
        adcq	r9, [%r8+72]
        movq	[%rcx+72], r9
        movq	r9, [%rdx+80]
        adcq	r9, [%r8+80]
        movq	[%rcx+80], r9
        movq	r9, [%rdx+88]
        adcq	r9, [%r8+88]
        movq	[%rcx+88], r9
        movq	r9, [%rdx+96]
        adcq	r9, [%r8+96]
        movq	[%rcx+96], r9
        movq	r9, [%rdx+104]
        adcq	r9, [%r8+104]
        movq	[%rcx+104], r9
        movq	r9, [%rdx+112]
        adcq	r9, [%r8+112]
        movq	[%rcx+112], r9
        movq	r9, [%rdx+120]
        adcq	r9, [%r8+120]
        movq	[%rcx+120], r9
        movq	r9, [%rdx+128]
        adcq	r9, [%r8+128]
        movq	[%rcx+128], r9
        movq	r9, [%rdx+136]
        adcq	r9, [%r8+136]
        movq	[%rcx+136], r9
        movq	r9, [%rdx+144]
        adcq	r9, [%r8+144]
        movq	[%rcx+144], r9
        movq	r9, [%rdx+152]
        adcq	r9, [%r8+152]
        movq	[%rcx+152], r9
        movq	r9, [%rdx+160]
        adcq	r9, [%r8+160]
        movq	[%rcx+160], r9
        movq	r9, [%rdx+168]
        adcq	r9, [%r8+168]
        movq	[%rcx+168], r9
        movq	r9, [%rdx+176]
        adcq	r9, [%r8+176]
        movq	[%rcx+176], r9
        movq	r9, [%rdx+184]
        adcq	r9, [%r8+184]
        movq	[%rcx+184], r9
        movq	r9, [%rdx+192]
        adcq	r9, [%r8+192]
        movq	[%rcx+192], r9
        movq	r9, [%rdx+200]
        adcq	r9, [%r8+200]
        movq	[%rcx+200], r9
        movq	r9, [%rdx+208]
        adcq	r9, [%r8+208]
        movq	[%rcx+208], r9
        movq	r9, [%rdx+216]
        adcq	r9, [%r8+216]
        movq	[%rcx+216], r9
        movq	r9, [%rdx+224]
        adcq	r9, [%r8+224]
        movq	[%rcx+224], r9
        movq	r9, [%rdx+232]
        adcq	r9, [%r8+232]
        movq	[%rcx+232], r9
        movq	r9, [%rdx+240]
        adcq	r9, [%r8+240]
        movq	[%rcx+240], r9
        movq	r9, [%rdx+248]
        adcq	r9, [%r8+248]
        movq	[%rcx+248], r9
        movq	r9, [%rdx+256]
        adcq	r9, [%r8+256]
        movq	[%rcx+256], r9
        movq	r9, [%rdx+264]
        adcq	r9, [%r8+264]
        movq	[%rcx+264], r9
        movq	r9, [%rdx+272]
        adcq	r9, [%r8+272]
        movq	[%rcx+272], r9
        movq	r9, [%rdx+280]
        adcq	r9, [%r8+280]
        movq	[%rcx+280], r9
        movq	r9, [%rdx+288]
        adcq	r9, [%r8+288]
        movq	[%rcx+288], r9
        movq	r9, [%rdx+296]
        adcq	r9, [%r8+296]
        movq	[%rcx+296], r9
        movq	r9, [%rdx+304]
        adcq	r9, [%r8+304]
        movq	[%rcx+304], r9
        movq	r9, [%rdx+312]
        adcq	r9, [%r8+312]
        movq	[%rcx+312], r9
        movq	r9, [%rdx+320]
        adcq	r9, [%r8+320]
        movq	[%rcx+320], r9
        movq	r9, [%rdx+328]
        adcq	r9, [%r8+328]
        movq	[%rcx+328], r9
        movq	r9, [%rdx+336]
        adcq	r9, [%r8+336]
        movq	[%rcx+336], r9
        movq	r9, [%rdx+344]
        adcq	r9, [%r8+344]
        movq	[%rcx+344], r9
        movq	r9, [%rdx+352]
        adcq	r9, [%r8+352]
        movq	[%rcx+352], r9
        movq	r9, [%rdx+360]
        adcq	r9, [%r8+360]
        movq	[%rcx+360], r9
        movq	r9, [%rdx+368]
        adcq	r9, [%r8+368]
        movq	[%rcx+368], r9
        movq	r9, [%rdx+376]
        adcq	r9, [%r8+376]
        movq	[%rcx+376], r9
        adcq	rax, 0
        repz retq
sp_3072_add_48 ENDP
; /* Mul a by digit b into r. (r = a * b)
;  *
;  * r  A single precision integer.
;  * a  A single precision integer.
;  * b  A single precision digit.
;  */
sp_3072_mul_d_48 PROC
        movq	rcx, rdx
        movq	r9, rcx
        push	r12
        ; A[0] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx]
        movq	r10, rax
        movq	r11, rdx
        movq	[%r9], r10
        ; A[1] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+8]
        addq	r11, rax
        movq	[%r9+8], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[2] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+16]
        addq	r12, rax
        movq	[%r9+16], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; A[3] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx+24]
        addq	r10, rax
        movq	[%r9+24], r10
        adcq	r11, rdx
        adcq	r12, 0
        ; A[4] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+32]
        addq	r11, rax
        movq	[%r9+32], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[5] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+40]
        addq	r12, rax
        movq	[%r9+40], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; A[6] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx+48]
        addq	r10, rax
        movq	[%r9+48], r10
        adcq	r11, rdx
        adcq	r12, 0
        ; A[7] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+56]
        addq	r11, rax
        movq	[%r9+56], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[8] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+64]
        addq	r12, rax
        movq	[%r9+64], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; A[9] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx+72]
        addq	r10, rax
        movq	[%r9+72], r10
        adcq	r11, rdx
        adcq	r12, 0
        ; A[10] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+80]
        addq	r11, rax
        movq	[%r9+80], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[11] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+88]
        addq	r12, rax
        movq	[%r9+88], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; A[12] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx+96]
        addq	r10, rax
        movq	[%r9+96], r10
        adcq	r11, rdx
        adcq	r12, 0
        ; A[13] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+104]
        addq	r11, rax
        movq	[%r9+104], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[14] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+112]
        addq	r12, rax
        movq	[%r9+112], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; A[15] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx+120]
        addq	r10, rax
        movq	[%r9+120], r10
        adcq	r11, rdx
        adcq	r12, 0
        ; A[16] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+128]
        addq	r11, rax
        movq	[%r9+128], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[17] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+136]
        addq	r12, rax
        movq	[%r9+136], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; A[18] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx+144]
        addq	r10, rax
        movq	[%r9+144], r10
        adcq	r11, rdx
        adcq	r12, 0
        ; A[19] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+152]
        addq	r11, rax
        movq	[%r9+152], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[20] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+160]
        addq	r12, rax
        movq	[%r9+160], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; A[21] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx+168]
        addq	r10, rax
        movq	[%r9+168], r10
        adcq	r11, rdx
        adcq	r12, 0
        ; A[22] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+176]
        addq	r11, rax
        movq	[%r9+176], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[23] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+184]
        addq	r12, rax
        movq	[%r9+184], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; A[24] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx+192]
        addq	r10, rax
        movq	[%r9+192], r10
        adcq	r11, rdx
        adcq	r12, 0
        ; A[25] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+200]
        addq	r11, rax
        movq	[%r9+200], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[26] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+208]
        addq	r12, rax
        movq	[%r9+208], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; A[27] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx+216]
        addq	r10, rax
        movq	[%r9+216], r10
        adcq	r11, rdx
        adcq	r12, 0
        ; A[28] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+224]
        addq	r11, rax
        movq	[%r9+224], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[29] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+232]
        addq	r12, rax
        movq	[%r9+232], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; A[30] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx+240]
        addq	r10, rax
        movq	[%r9+240], r10
        adcq	r11, rdx
        adcq	r12, 0
        ; A[31] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+248]
        addq	r11, rax
        movq	[%r9+248], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[32] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+256]
        addq	r12, rax
        movq	[%r9+256], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; A[33] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx+264]
        addq	r10, rax
        movq	[%r9+264], r10
        adcq	r11, rdx
        adcq	r12, 0
        ; A[34] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+272]
        addq	r11, rax
        movq	[%r9+272], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[35] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+280]
        addq	r12, rax
        movq	[%r9+280], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; A[36] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx+288]
        addq	r10, rax
        movq	[%r9+288], r10
        adcq	r11, rdx
        adcq	r12, 0
        ; A[37] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+296]
        addq	r11, rax
        movq	[%r9+296], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[38] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+304]
        addq	r12, rax
        movq	[%r9+304], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; A[39] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx+312]
        addq	r10, rax
        movq	[%r9+312], r10
        adcq	r11, rdx
        adcq	r12, 0
        ; A[40] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+320]
        addq	r11, rax
        movq	[%r9+320], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[41] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+328]
        addq	r12, rax
        movq	[%r9+328], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; A[42] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx+336]
        addq	r10, rax
        movq	[%r9+336], r10
        adcq	r11, rdx
        adcq	r12, 0
        ; A[43] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+344]
        addq	r11, rax
        movq	[%r9+344], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[44] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+352]
        addq	r12, rax
        movq	[%r9+352], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; A[45] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx+360]
        addq	r10, rax
        movq	[%r9+360], r10
        adcq	r11, rdx
        adcq	r12, 0
        ; A[46] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+368]
        addq	r11, rax
        movq	[%r9+368], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; # A[47] * B
        movq	rax, r8
        mulq	[%rcx+376]
        addq	r12, rax
        adcq	r10, rdx
        movq	[%r9+376], r12
        movq	[%r9+384], r10
        pop	r12
        repz retq
sp_3072_mul_d_48 ENDP
; /* Sub b from a into a. (a -= b)
;  *
;  * a  A single precision integer and result.
;  * b  A single precision integer.
;  */
sp_3072_sub_in_place_24 PROC
        xorq	rax, rax
        movq	r8, [%rcx]
        movq	r9, [%rcx+8]
        movq	r10, [%rdx]
        movq	r11, [%rdx+8]
        subq	r8, r10
        movq	r10, [%rdx+16]
        movq	[%rcx], r8
        movq	r8, [%rcx+16]
        sbbq	r9, r11
        movq	r11, [%rdx+24]
        movq	[%rcx+8], r9
        movq	r9, [%rcx+24]
        sbbq	r8, r10
        movq	r10, [%rdx+32]
        movq	[%rcx+16], r8
        movq	r8, [%rcx+32]
        sbbq	r9, r11
        movq	r11, [%rdx+40]
        movq	[%rcx+24], r9
        movq	r9, [%rcx+40]
        sbbq	r8, r10
        movq	r10, [%rdx+48]
        movq	[%rcx+32], r8
        movq	r8, [%rcx+48]
        sbbq	r9, r11
        movq	r11, [%rdx+56]
        movq	[%rcx+40], r9
        movq	r9, [%rcx+56]
        sbbq	r8, r10
        movq	r10, [%rdx+64]
        movq	[%rcx+48], r8
        movq	r8, [%rcx+64]
        sbbq	r9, r11
        movq	r11, [%rdx+72]
        movq	[%rcx+56], r9
        movq	r9, [%rcx+72]
        sbbq	r8, r10
        movq	r10, [%rdx+80]
        movq	[%rcx+64], r8
        movq	r8, [%rcx+80]
        sbbq	r9, r11
        movq	r11, [%rdx+88]
        movq	[%rcx+72], r9
        movq	r9, [%rcx+88]
        sbbq	r8, r10
        movq	r10, [%rdx+96]
        movq	[%rcx+80], r8
        movq	r8, [%rcx+96]
        sbbq	r9, r11
        movq	r11, [%rdx+104]
        movq	[%rcx+88], r9
        movq	r9, [%rcx+104]
        sbbq	r8, r10
        movq	r10, [%rdx+112]
        movq	[%rcx+96], r8
        movq	r8, [%rcx+112]
        sbbq	r9, r11
        movq	r11, [%rdx+120]
        movq	[%rcx+104], r9
        movq	r9, [%rcx+120]
        sbbq	r8, r10
        movq	r10, [%rdx+128]
        movq	[%rcx+112], r8
        movq	r8, [%rcx+128]
        sbbq	r9, r11
        movq	r11, [%rdx+136]
        movq	[%rcx+120], r9
        movq	r9, [%rcx+136]
        sbbq	r8, r10
        movq	r10, [%rdx+144]
        movq	[%rcx+128], r8
        movq	r8, [%rcx+144]
        sbbq	r9, r11
        movq	r11, [%rdx+152]
        movq	[%rcx+136], r9
        movq	r9, [%rcx+152]
        sbbq	r8, r10
        movq	r10, [%rdx+160]
        movq	[%rcx+144], r8
        movq	r8, [%rcx+160]
        sbbq	r9, r11
        movq	r11, [%rdx+168]
        movq	[%rcx+152], r9
        movq	r9, [%rcx+168]
        sbbq	r8, r10
        movq	r10, [%rdx+176]
        movq	[%rcx+160], r8
        movq	r8, [%rcx+176]
        sbbq	r9, r11
        movq	r11, [%rdx+184]
        movq	[%rcx+168], r9
        movq	r9, [%rcx+184]
        sbbq	r8, r10
        movq	[%rcx+176], r8
        sbbq	r9, r11
        movq	[%rcx+184], r9
        sbbq	rax, 0
        repz retq
sp_3072_sub_in_place_24 ENDP
; /* Conditionally subtract b from a using the mask m.
;  * m is -1 to subtract and 0 when not copying.
;  *
;  * r  A single precision number representing condition subtract result.
;  * a  A single precision number to subtract from.
;  * b  A single precision number to subtract.
;  * m  Mask value to apply.
;  */
sp_3072_cond_sub_24 PROC
        subq	rsp, 192
        movq	rax, 0
        movq	r10, [%r8]
        movq	r11, [%r8+8]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp], r10
        movq	[%rsp+8], r11
        movq	r10, [%r8+16]
        movq	r11, [%r8+24]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+16], r10
        movq	[%rsp+24], r11
        movq	r10, [%r8+32]
        movq	r11, [%r8+40]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+32], r10
        movq	[%rsp+40], r11
        movq	r10, [%r8+48]
        movq	r11, [%r8+56]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+48], r10
        movq	[%rsp+56], r11
        movq	r10, [%r8+64]
        movq	r11, [%r8+72]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+64], r10
        movq	[%rsp+72], r11
        movq	r10, [%r8+80]
        movq	r11, [%r8+88]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+80], r10
        movq	[%rsp+88], r11
        movq	r10, [%r8+96]
        movq	r11, [%r8+104]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+96], r10
        movq	[%rsp+104], r11
        movq	r10, [%r8+112]
        movq	r11, [%r8+120]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+112], r10
        movq	[%rsp+120], r11
        movq	r10, [%r8+128]
        movq	r11, [%r8+136]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+128], r10
        movq	[%rsp+136], r11
        movq	r10, [%r8+144]
        movq	r11, [%r8+152]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+144], r10
        movq	[%rsp+152], r11
        movq	r10, [%r8+160]
        movq	r11, [%r8+168]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+160], r10
        movq	[%rsp+168], r11
        movq	r10, [%r8+176]
        movq	r11, [%r8+184]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+176], r10
        movq	[%rsp+184], r11
        movq	r10, [%rdx]
        movq	r8, [%rsp]
        subq	r10, r8
        movq	r11, [%rdx+8]
        movq	r8, [%rsp+8]
        sbbq	r11, r8
        movq	[%rcx], r10
        movq	r10, [%rdx+16]
        movq	r8, [%rsp+16]
        sbbq	r10, r8
        movq	[%rcx+8], r11
        movq	r11, [%rdx+24]
        movq	r8, [%rsp+24]
        sbbq	r11, r8
        movq	[%rcx+16], r10
        movq	r10, [%rdx+32]
        movq	r8, [%rsp+32]
        sbbq	r10, r8
        movq	[%rcx+24], r11
        movq	r11, [%rdx+40]
        movq	r8, [%rsp+40]
        sbbq	r11, r8
        movq	[%rcx+32], r10
        movq	r10, [%rdx+48]
        movq	r8, [%rsp+48]
        sbbq	r10, r8
        movq	[%rcx+40], r11
        movq	r11, [%rdx+56]
        movq	r8, [%rsp+56]
        sbbq	r11, r8
        movq	[%rcx+48], r10
        movq	r10, [%rdx+64]
        movq	r8, [%rsp+64]
        sbbq	r10, r8
        movq	[%rcx+56], r11
        movq	r11, [%rdx+72]
        movq	r8, [%rsp+72]
        sbbq	r11, r8
        movq	[%rcx+64], r10
        movq	r10, [%rdx+80]
        movq	r8, [%rsp+80]
        sbbq	r10, r8
        movq	[%rcx+72], r11
        movq	r11, [%rdx+88]
        movq	r8, [%rsp+88]
        sbbq	r11, r8
        movq	[%rcx+80], r10
        movq	r10, [%rdx+96]
        movq	r8, [%rsp+96]
        sbbq	r10, r8
        movq	[%rcx+88], r11
        movq	r11, [%rdx+104]
        movq	r8, [%rsp+104]
        sbbq	r11, r8
        movq	[%rcx+96], r10
        movq	r10, [%rdx+112]
        movq	r8, [%rsp+112]
        sbbq	r10, r8
        movq	[%rcx+104], r11
        movq	r11, [%rdx+120]
        movq	r8, [%rsp+120]
        sbbq	r11, r8
        movq	[%rcx+112], r10
        movq	r10, [%rdx+128]
        movq	r8, [%rsp+128]
        sbbq	r10, r8
        movq	[%rcx+120], r11
        movq	r11, [%rdx+136]
        movq	r8, [%rsp+136]
        sbbq	r11, r8
        movq	[%rcx+128], r10
        movq	r10, [%rdx+144]
        movq	r8, [%rsp+144]
        sbbq	r10, r8
        movq	[%rcx+136], r11
        movq	r11, [%rdx+152]
        movq	r8, [%rsp+152]
        sbbq	r11, r8
        movq	[%rcx+144], r10
        movq	r10, [%rdx+160]
        movq	r8, [%rsp+160]
        sbbq	r10, r8
        movq	[%rcx+152], r11
        movq	r11, [%rdx+168]
        movq	r8, [%rsp+168]
        sbbq	r11, r8
        movq	[%rcx+160], r10
        movq	r10, [%rdx+176]
        movq	r8, [%rsp+176]
        sbbq	r10, r8
        movq	[%rcx+168], r11
        movq	r11, [%rdx+184]
        movq	r8, [%rsp+184]
        sbbq	r11, r8
        movq	[%rcx+176], r10
        movq	[%rcx+184], r11
        sbbq	rax, 0
        addq	rsp, 192
        repz retq
sp_3072_cond_sub_24 ENDP
; /* Reduce the number back to 3072 bits using Montgomery reduction.
;  *
;  * a   A single precision number to reduce in place.
;  * m   The single precision number representing the modulus.
;  * mp  The digit representing the negative inverse of m mod 2^n.
;  */
sp_3072_mont_reduce_24 PROC
        movq	rcx, rdx
        movq	r9, rcx
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        xorq	rsi, rsi
        ; i = 0
        movq	r10, 24
        movq	r15, [%r9]
        movq	rdi, [%r9+8]
L_mont_loop_24:
        ; mu = a[i] * mp
        movq	r13, r15
        imulq	r13, r8
        ; a[i+0] += m[0] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx]
        addq	r15, rax
        adcq	r12, rdx
        ; a[i+1] += m[1] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+8]
        movq	r15, rdi
        addq	r15, rax
        adcq	r11, rdx
        addq	r15, r12
        adcq	r11, 0
        ; a[i+2] += m[2] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+16]
        movq	rdi, [%r9+16]
        addq	rdi, rax
        adcq	r12, rdx
        addq	rdi, r11
        adcq	r12, 0
        ; a[i+3] += m[3] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+24]
        movq	r14, [%r9+24]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+24], r14
        adcq	r11, 0
        ; a[i+4] += m[4] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+32]
        movq	r14, [%r9+32]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+32], r14
        adcq	r12, 0
        ; a[i+5] += m[5] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+40]
        movq	r14, [%r9+40]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+40], r14
        adcq	r11, 0
        ; a[i+6] += m[6] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+48]
        movq	r14, [%r9+48]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+48], r14
        adcq	r12, 0
        ; a[i+7] += m[7] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+56]
        movq	r14, [%r9+56]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+56], r14
        adcq	r11, 0
        ; a[i+8] += m[8] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+64]
        movq	r14, [%r9+64]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+64], r14
        adcq	r12, 0
        ; a[i+9] += m[9] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+72]
        movq	r14, [%r9+72]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+72], r14
        adcq	r11, 0
        ; a[i+10] += m[10] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+80]
        movq	r14, [%r9+80]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+80], r14
        adcq	r12, 0
        ; a[i+11] += m[11] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+88]
        movq	r14, [%r9+88]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+88], r14
        adcq	r11, 0
        ; a[i+12] += m[12] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+96]
        movq	r14, [%r9+96]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+96], r14
        adcq	r12, 0
        ; a[i+13] += m[13] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+104]
        movq	r14, [%r9+104]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+104], r14
        adcq	r11, 0
        ; a[i+14] += m[14] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+112]
        movq	r14, [%r9+112]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+112], r14
        adcq	r12, 0
        ; a[i+15] += m[15] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+120]
        movq	r14, [%r9+120]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+120], r14
        adcq	r11, 0
        ; a[i+16] += m[16] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+128]
        movq	r14, [%r9+128]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+128], r14
        adcq	r12, 0
        ; a[i+17] += m[17] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+136]
        movq	r14, [%r9+136]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+136], r14
        adcq	r11, 0
        ; a[i+18] += m[18] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+144]
        movq	r14, [%r9+144]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+144], r14
        adcq	r12, 0
        ; a[i+19] += m[19] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+152]
        movq	r14, [%r9+152]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+152], r14
        adcq	r11, 0
        ; a[i+20] += m[20] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+160]
        movq	r14, [%r9+160]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+160], r14
        adcq	r12, 0
        ; a[i+21] += m[21] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+168]
        movq	r14, [%r9+168]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+168], r14
        adcq	r11, 0
        ; a[i+22] += m[22] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+176]
        movq	r14, [%r9+176]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+176], r14
        adcq	r12, 0
        ; a[i+23] += m[23] * mu
        movq	rax, r13
        mulq	[%rcx+184]
        movq	r14, [%r9+184]
        addq	r12, rax
        adcq	rdx, rsi
        movq	rsi, 0
        adcq	rsi, 0
        addq	r14, r12
        movq	[%r9+184], r14
        adcq	[%r9+192], rdx
        adcq	rsi, 0
        ; i += 1
        addq	r9, 8
        decq	r10
        jnz	L_mont_loop_24
        movq	[%r9], r15
        movq	[%r9+8], rdi
        negq	rsi
        movq	r9, rsi
        movq	r8, rcx
        movq	rdx, r9
        movq	rcx, r9
        subq	rcx, 192
        callq	sp_3072_cond_sub_24
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        repz retq
sp_3072_mont_reduce_24 ENDP
; /* Mul a by digit b into r. (r = a * b)
;  *
;  * r  A single precision integer.
;  * a  A single precision integer.
;  * b  A single precision digit.
;  */
sp_3072_mul_d_24 PROC
        movq	rcx, rdx
        movq	r9, rcx
        push	r12
        ; A[0] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx]
        movq	r10, rax
        movq	r11, rdx
        movq	[%r9], r10
        ; A[1] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+8]
        addq	r11, rax
        movq	[%r9+8], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[2] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+16]
        addq	r12, rax
        movq	[%r9+16], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; A[3] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx+24]
        addq	r10, rax
        movq	[%r9+24], r10
        adcq	r11, rdx
        adcq	r12, 0
        ; A[4] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+32]
        addq	r11, rax
        movq	[%r9+32], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[5] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+40]
        addq	r12, rax
        movq	[%r9+40], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; A[6] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx+48]
        addq	r10, rax
        movq	[%r9+48], r10
        adcq	r11, rdx
        adcq	r12, 0
        ; A[7] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+56]
        addq	r11, rax
        movq	[%r9+56], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[8] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+64]
        addq	r12, rax
        movq	[%r9+64], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; A[9] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx+72]
        addq	r10, rax
        movq	[%r9+72], r10
        adcq	r11, rdx
        adcq	r12, 0
        ; A[10] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+80]
        addq	r11, rax
        movq	[%r9+80], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[11] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+88]
        addq	r12, rax
        movq	[%r9+88], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; A[12] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx+96]
        addq	r10, rax
        movq	[%r9+96], r10
        adcq	r11, rdx
        adcq	r12, 0
        ; A[13] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+104]
        addq	r11, rax
        movq	[%r9+104], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[14] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+112]
        addq	r12, rax
        movq	[%r9+112], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; A[15] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx+120]
        addq	r10, rax
        movq	[%r9+120], r10
        adcq	r11, rdx
        adcq	r12, 0
        ; A[16] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+128]
        addq	r11, rax
        movq	[%r9+128], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[17] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+136]
        addq	r12, rax
        movq	[%r9+136], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; A[18] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx+144]
        addq	r10, rax
        movq	[%r9+144], r10
        adcq	r11, rdx
        adcq	r12, 0
        ; A[19] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+152]
        addq	r11, rax
        movq	[%r9+152], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[20] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+160]
        addq	r12, rax
        movq	[%r9+160], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; A[21] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx+168]
        addq	r10, rax
        movq	[%r9+168], r10
        adcq	r11, rdx
        adcq	r12, 0
        ; A[22] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+176]
        addq	r11, rax
        movq	[%r9+176], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; # A[23] * B
        movq	rax, r8
        mulq	[%rcx+184]
        addq	r12, rax
        adcq	r10, rdx
        movq	[%r9+184], r12
        movq	[%r9+192], r10
        pop	r12
        repz retq
sp_3072_mul_d_24 ENDP
IFDEF HAVE_INTEL_AVX2
; /* Mul a by digit b into r. (r = a * b)
;  *
;  * r  A single precision integer.
;  * a  A single precision integer.
;  * b  A single precision digit.
;  */
sp_3072_mul_d_avx2_24 PROC
        movq	rax, rdx
        push	r12
        push	r13
        ; A[0] * B
        movq	rdx, r8
        xorq	r13, r13
        mulxq	r12, r11, [%rax]
        movq	[%rcx], r11
        ; A[1] * B
        mulxq	r10, r9, [%rax+8]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+8], r12
        adoxq	r11, r10
        ; A[2] * B
        mulxq	r10, r9, [%rax+16]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+16], r11
        adoxq	r12, r10
        ; A[3] * B
        mulxq	r10, r9, [%rax+24]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+24], r12
        adoxq	r11, r10
        ; A[4] * B
        mulxq	r10, r9, [%rax+32]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+32], r11
        adoxq	r12, r10
        ; A[5] * B
        mulxq	r10, r9, [%rax+40]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+40], r12
        adoxq	r11, r10
        ; A[6] * B
        mulxq	r10, r9, [%rax+48]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+48], r11
        adoxq	r12, r10
        ; A[7] * B
        mulxq	r10, r9, [%rax+56]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+56], r12
        adoxq	r11, r10
        ; A[8] * B
        mulxq	r10, r9, [%rax+64]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+64], r11
        adoxq	r12, r10
        ; A[9] * B
        mulxq	r10, r9, [%rax+72]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+72], r12
        adoxq	r11, r10
        ; A[10] * B
        mulxq	r10, r9, [%rax+80]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+80], r11
        adoxq	r12, r10
        ; A[11] * B
        mulxq	r10, r9, [%rax+88]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+88], r12
        adoxq	r11, r10
        ; A[12] * B
        mulxq	r10, r9, [%rax+96]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+96], r11
        adoxq	r12, r10
        ; A[13] * B
        mulxq	r10, r9, [%rax+104]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+104], r12
        adoxq	r11, r10
        ; A[14] * B
        mulxq	r10, r9, [%rax+112]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+112], r11
        adoxq	r12, r10
        ; A[15] * B
        mulxq	r10, r9, [%rax+120]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+120], r12
        adoxq	r11, r10
        ; A[16] * B
        mulxq	r10, r9, [%rax+128]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+128], r11
        adoxq	r12, r10
        ; A[17] * B
        mulxq	r10, r9, [%rax+136]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+136], r12
        adoxq	r11, r10
        ; A[18] * B
        mulxq	r10, r9, [%rax+144]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+144], r11
        adoxq	r12, r10
        ; A[19] * B
        mulxq	r10, r9, [%rax+152]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+152], r12
        adoxq	r11, r10
        ; A[20] * B
        mulxq	r10, r9, [%rax+160]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+160], r11
        adoxq	r12, r10
        ; A[21] * B
        mulxq	r10, r9, [%rax+168]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+168], r12
        adoxq	r11, r10
        ; A[22] * B
        mulxq	r10, r9, [%rax+176]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+176], r11
        adoxq	r12, r10
        ; A[23] * B
        mulxq	r10, r9, [%rax+184]
        movq	r11, r13
        adcxq	r12, r9
        adoxq	r11, r10
        adcxq	r11, r13
        movq	[%rcx+184], r12
        movq	[%rcx+192], r11
        pop	r13
        pop	r12
        repz retq
sp_3072_mul_d_avx2_24 ENDP
ENDIF
; /* Compare a with b in constant time.
;  *
;  * a  A single precision integer.
;  * b  A single precision integer.
;  * return -ve, 0 or +ve if a is less than, equal to or greater than b
;  * respectively.
;  */
sp_3072_cmp_24 PROC
        push	r12
        xorq	r9, r9
        movq	r8, -1
        movq	rax, -1
        movq	r10, 1
        movq	r11, [%rcx+184]
        movq	r12, [%rdx+184]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+176]
        movq	r12, [%rdx+176]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+168]
        movq	r12, [%rdx+168]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+160]
        movq	r12, [%rdx+160]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+152]
        movq	r12, [%rdx+152]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+144]
        movq	r12, [%rdx+144]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+136]
        movq	r12, [%rdx+136]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+128]
        movq	r12, [%rdx+128]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+120]
        movq	r12, [%rdx+120]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+112]
        movq	r12, [%rdx+112]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+104]
        movq	r12, [%rdx+104]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+96]
        movq	r12, [%rdx+96]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+88]
        movq	r12, [%rdx+88]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+80]
        movq	r12, [%rdx+80]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+72]
        movq	r12, [%rdx+72]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+64]
        movq	r12, [%rdx+64]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+56]
        movq	r12, [%rdx+56]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+48]
        movq	r12, [%rdx+48]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+40]
        movq	r12, [%rdx+40]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+32]
        movq	r12, [%rdx+32]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+24]
        movq	r12, [%rdx+24]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+16]
        movq	r12, [%rdx+16]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+8]
        movq	r12, [%rdx+8]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx]
        movq	r12, [%rdx]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        xorq	rax, r8
        pop	r12
        repz retq
sp_3072_cmp_24 ENDP
IFDEF HAVE_INTEL_AVX2
; /* Reduce the number back to 3072 bits using Montgomery reduction.
;  *
;  * a   A single precision number to reduce in place.
;  * m   The single precision number representing the modulus.
;  * mp  The digit representing the negative inverse of m mod 2^n.
;  */
sp_3072_mont_reduce_avx2_24 PROC
        movq	rax, rdx
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        xorq	rdi, rdi
        ; i = 0
        movq	r11, 24
        movq	r15, [%rcx]
        xorq	r14, r14
L_mont_loop_avx2_24:
        ; mu = a[i] * mp
        movq	rdx, r15
        mulxq	r10, rdx, r8
        movq	r12, r15
        ; a[i+0] += m[0] * mu
        mulxq	r10, r9, [%rax]
        movq	r15, [%rcx+8]
        adcxq	r12, r9
        adoxq	r15, r10
        ; a[i+1] += m[1] * mu
        mulxq	r10, r9, [%rax+8]
        movq	r12, [%rcx+16]
        adcxq	r15, r9
        adoxq	r12, r10
        ; a[i+2] += m[2] * mu
        mulxq	r10, r9, [%rax+16]
        movq	r13, [%rcx+24]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+16], r12
        ; a[i+3] += m[3] * mu
        mulxq	r10, r9, [%rax+24]
        movq	r12, [%rcx+32]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+24], r13
        ; a[i+4] += m[4] * mu
        mulxq	r10, r9, [%rax+32]
        movq	r13, [%rcx+40]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+32], r12
        ; a[i+5] += m[5] * mu
        mulxq	r10, r9, [%rax+40]
        movq	r12, [%rcx+48]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+40], r13
        ; a[i+6] += m[6] * mu
        mulxq	r10, r9, [%rax+48]
        movq	r13, [%rcx+56]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+48], r12
        ; a[i+7] += m[7] * mu
        mulxq	r10, r9, [%rax+56]
        movq	r12, [%rcx+64]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+56], r13
        ; a[i+8] += m[8] * mu
        mulxq	r10, r9, [%rax+64]
        movq	r13, [%rcx+72]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+64], r12
        ; a[i+9] += m[9] * mu
        mulxq	r10, r9, [%rax+72]
        movq	r12, [%rcx+80]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+72], r13
        ; a[i+10] += m[10] * mu
        mulxq	r10, r9, [%rax+80]
        movq	r13, [%rcx+88]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+80], r12
        ; a[i+11] += m[11] * mu
        mulxq	r10, r9, [%rax+88]
        movq	r12, [%rcx+96]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+88], r13
        ; a[i+12] += m[12] * mu
        mulxq	r10, r9, [%rax+96]
        movq	r13, [%rcx+104]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+96], r12
        ; a[i+13] += m[13] * mu
        mulxq	r10, r9, [%rax+104]
        movq	r12, [%rcx+112]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+104], r13
        ; a[i+14] += m[14] * mu
        mulxq	r10, r9, [%rax+112]
        movq	r13, [%rcx+120]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+112], r12
        ; a[i+15] += m[15] * mu
        mulxq	r10, r9, [%rax+120]
        movq	r12, [%rcx+128]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+120], r13
        ; a[i+16] += m[16] * mu
        mulxq	r10, r9, [%rax+128]
        movq	r13, [%rcx+136]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+128], r12
        ; a[i+17] += m[17] * mu
        mulxq	r10, r9, [%rax+136]
        movq	r12, [%rcx+144]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+136], r13
        ; a[i+18] += m[18] * mu
        mulxq	r10, r9, [%rax+144]
        movq	r13, [%rcx+152]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+144], r12
        ; a[i+19] += m[19] * mu
        mulxq	r10, r9, [%rax+152]
        movq	r12, [%rcx+160]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+152], r13
        ; a[i+20] += m[20] * mu
        mulxq	r10, r9, [%rax+160]
        movq	r13, [%rcx+168]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+160], r12
        ; a[i+21] += m[21] * mu
        mulxq	r10, r9, [%rax+168]
        movq	r12, [%rcx+176]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+168], r13
        ; a[i+22] += m[22] * mu
        mulxq	r10, r9, [%rax+176]
        movq	r13, [%rcx+184]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+176], r12
        ; a[i+23] += m[23] * mu
        mulxq	r10, r9, [%rax+184]
        movq	r12, [%rcx+192]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+184], r13
        adcxq	r12, rdi
        movq	rdi, r14
        adoxq	rdi, r14
        adcxq	rdi, r14
        movq	[%rcx+192], r12
        ; i += 1
        addq	rcx, 8
        decq	r11
        jnz	L_mont_loop_avx2_24
        movq	[%rcx], r15
        negq	rdi
        movq	r9, rdi
        movq	r8, rax
        movq	rdx, rcx
        movq	rcx, rcx
        subq	rcx, 192
        callq	sp_3072_cond_sub_24
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        repz retq
sp_3072_mont_reduce_avx2_24 ENDP
ENDIF
; /* Conditionally subtract b from a using the mask m.
;  * m is -1 to subtract and 0 when not copying.
;  *
;  * r  A single precision number representing condition subtract result.
;  * a  A single precision number to subtract from.
;  * b  A single precision number to subtract.
;  * m  Mask value to apply.
;  */
sp_3072_cond_sub_48 PROC
        subq	rsp, 384
        movq	rax, 0
        movq	r10, [%r8]
        movq	r11, [%r8+8]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp], r10
        movq	[%rsp+8], r11
        movq	r10, [%r8+16]
        movq	r11, [%r8+24]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+16], r10
        movq	[%rsp+24], r11
        movq	r10, [%r8+32]
        movq	r11, [%r8+40]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+32], r10
        movq	[%rsp+40], r11
        movq	r10, [%r8+48]
        movq	r11, [%r8+56]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+48], r10
        movq	[%rsp+56], r11
        movq	r10, [%r8+64]
        movq	r11, [%r8+72]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+64], r10
        movq	[%rsp+72], r11
        movq	r10, [%r8+80]
        movq	r11, [%r8+88]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+80], r10
        movq	[%rsp+88], r11
        movq	r10, [%r8+96]
        movq	r11, [%r8+104]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+96], r10
        movq	[%rsp+104], r11
        movq	r10, [%r8+112]
        movq	r11, [%r8+120]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+112], r10
        movq	[%rsp+120], r11
        movq	r10, [%r8+128]
        movq	r11, [%r8+136]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+128], r10
        movq	[%rsp+136], r11
        movq	r10, [%r8+144]
        movq	r11, [%r8+152]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+144], r10
        movq	[%rsp+152], r11
        movq	r10, [%r8+160]
        movq	r11, [%r8+168]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+160], r10
        movq	[%rsp+168], r11
        movq	r10, [%r8+176]
        movq	r11, [%r8+184]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+176], r10
        movq	[%rsp+184], r11
        movq	r10, [%r8+192]
        movq	r11, [%r8+200]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+192], r10
        movq	[%rsp+200], r11
        movq	r10, [%r8+208]
        movq	r11, [%r8+216]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+208], r10
        movq	[%rsp+216], r11
        movq	r10, [%r8+224]
        movq	r11, [%r8+232]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+224], r10
        movq	[%rsp+232], r11
        movq	r10, [%r8+240]
        movq	r11, [%r8+248]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+240], r10
        movq	[%rsp+248], r11
        movq	r10, [%r8+256]
        movq	r11, [%r8+264]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+256], r10
        movq	[%rsp+264], r11
        movq	r10, [%r8+272]
        movq	r11, [%r8+280]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+272], r10
        movq	[%rsp+280], r11
        movq	r10, [%r8+288]
        movq	r11, [%r8+296]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+288], r10
        movq	[%rsp+296], r11
        movq	r10, [%r8+304]
        movq	r11, [%r8+312]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+304], r10
        movq	[%rsp+312], r11
        movq	r10, [%r8+320]
        movq	r11, [%r8+328]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+320], r10
        movq	[%rsp+328], r11
        movq	r10, [%r8+336]
        movq	r11, [%r8+344]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+336], r10
        movq	[%rsp+344], r11
        movq	r10, [%r8+352]
        movq	r11, [%r8+360]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+352], r10
        movq	[%rsp+360], r11
        movq	r10, [%r8+368]
        movq	r11, [%r8+376]
        andq	r10, r9
        andq	r11, r9
        movq	[%rsp+368], r10
        movq	[%rsp+376], r11
        movq	r10, [%rdx]
        movq	r8, [%rsp]
        subq	r10, r8
        movq	r11, [%rdx+8]
        movq	r8, [%rsp+8]
        sbbq	r11, r8
        movq	[%rcx], r10
        movq	r10, [%rdx+16]
        movq	r8, [%rsp+16]
        sbbq	r10, r8
        movq	[%rcx+8], r11
        movq	r11, [%rdx+24]
        movq	r8, [%rsp+24]
        sbbq	r11, r8
        movq	[%rcx+16], r10
        movq	r10, [%rdx+32]
        movq	r8, [%rsp+32]
        sbbq	r10, r8
        movq	[%rcx+24], r11
        movq	r11, [%rdx+40]
        movq	r8, [%rsp+40]
        sbbq	r11, r8
        movq	[%rcx+32], r10
        movq	r10, [%rdx+48]
        movq	r8, [%rsp+48]
        sbbq	r10, r8
        movq	[%rcx+40], r11
        movq	r11, [%rdx+56]
        movq	r8, [%rsp+56]
        sbbq	r11, r8
        movq	[%rcx+48], r10
        movq	r10, [%rdx+64]
        movq	r8, [%rsp+64]
        sbbq	r10, r8
        movq	[%rcx+56], r11
        movq	r11, [%rdx+72]
        movq	r8, [%rsp+72]
        sbbq	r11, r8
        movq	[%rcx+64], r10
        movq	r10, [%rdx+80]
        movq	r8, [%rsp+80]
        sbbq	r10, r8
        movq	[%rcx+72], r11
        movq	r11, [%rdx+88]
        movq	r8, [%rsp+88]
        sbbq	r11, r8
        movq	[%rcx+80], r10
        movq	r10, [%rdx+96]
        movq	r8, [%rsp+96]
        sbbq	r10, r8
        movq	[%rcx+88], r11
        movq	r11, [%rdx+104]
        movq	r8, [%rsp+104]
        sbbq	r11, r8
        movq	[%rcx+96], r10
        movq	r10, [%rdx+112]
        movq	r8, [%rsp+112]
        sbbq	r10, r8
        movq	[%rcx+104], r11
        movq	r11, [%rdx+120]
        movq	r8, [%rsp+120]
        sbbq	r11, r8
        movq	[%rcx+112], r10
        movq	r10, [%rdx+128]
        movq	r8, [%rsp+128]
        sbbq	r10, r8
        movq	[%rcx+120], r11
        movq	r11, [%rdx+136]
        movq	r8, [%rsp+136]
        sbbq	r11, r8
        movq	[%rcx+128], r10
        movq	r10, [%rdx+144]
        movq	r8, [%rsp+144]
        sbbq	r10, r8
        movq	[%rcx+136], r11
        movq	r11, [%rdx+152]
        movq	r8, [%rsp+152]
        sbbq	r11, r8
        movq	[%rcx+144], r10
        movq	r10, [%rdx+160]
        movq	r8, [%rsp+160]
        sbbq	r10, r8
        movq	[%rcx+152], r11
        movq	r11, [%rdx+168]
        movq	r8, [%rsp+168]
        sbbq	r11, r8
        movq	[%rcx+160], r10
        movq	r10, [%rdx+176]
        movq	r8, [%rsp+176]
        sbbq	r10, r8
        movq	[%rcx+168], r11
        movq	r11, [%rdx+184]
        movq	r8, [%rsp+184]
        sbbq	r11, r8
        movq	[%rcx+176], r10
        movq	r10, [%rdx+192]
        movq	r8, [%rsp+192]
        sbbq	r10, r8
        movq	[%rcx+184], r11
        movq	r11, [%rdx+200]
        movq	r8, [%rsp+200]
        sbbq	r11, r8
        movq	[%rcx+192], r10
        movq	r10, [%rdx+208]
        movq	r8, [%rsp+208]
        sbbq	r10, r8
        movq	[%rcx+200], r11
        movq	r11, [%rdx+216]
        movq	r8, [%rsp+216]
        sbbq	r11, r8
        movq	[%rcx+208], r10
        movq	r10, [%rdx+224]
        movq	r8, [%rsp+224]
        sbbq	r10, r8
        movq	[%rcx+216], r11
        movq	r11, [%rdx+232]
        movq	r8, [%rsp+232]
        sbbq	r11, r8
        movq	[%rcx+224], r10
        movq	r10, [%rdx+240]
        movq	r8, [%rsp+240]
        sbbq	r10, r8
        movq	[%rcx+232], r11
        movq	r11, [%rdx+248]
        movq	r8, [%rsp+248]
        sbbq	r11, r8
        movq	[%rcx+240], r10
        movq	r10, [%rdx+256]
        movq	r8, [%rsp+256]
        sbbq	r10, r8
        movq	[%rcx+248], r11
        movq	r11, [%rdx+264]
        movq	r8, [%rsp+264]
        sbbq	r11, r8
        movq	[%rcx+256], r10
        movq	r10, [%rdx+272]
        movq	r8, [%rsp+272]
        sbbq	r10, r8
        movq	[%rcx+264], r11
        movq	r11, [%rdx+280]
        movq	r8, [%rsp+280]
        sbbq	r11, r8
        movq	[%rcx+272], r10
        movq	r10, [%rdx+288]
        movq	r8, [%rsp+288]
        sbbq	r10, r8
        movq	[%rcx+280], r11
        movq	r11, [%rdx+296]
        movq	r8, [%rsp+296]
        sbbq	r11, r8
        movq	[%rcx+288], r10
        movq	r10, [%rdx+304]
        movq	r8, [%rsp+304]
        sbbq	r10, r8
        movq	[%rcx+296], r11
        movq	r11, [%rdx+312]
        movq	r8, [%rsp+312]
        sbbq	r11, r8
        movq	[%rcx+304], r10
        movq	r10, [%rdx+320]
        movq	r8, [%rsp+320]
        sbbq	r10, r8
        movq	[%rcx+312], r11
        movq	r11, [%rdx+328]
        movq	r8, [%rsp+328]
        sbbq	r11, r8
        movq	[%rcx+320], r10
        movq	r10, [%rdx+336]
        movq	r8, [%rsp+336]
        sbbq	r10, r8
        movq	[%rcx+328], r11
        movq	r11, [%rdx+344]
        movq	r8, [%rsp+344]
        sbbq	r11, r8
        movq	[%rcx+336], r10
        movq	r10, [%rdx+352]
        movq	r8, [%rsp+352]
        sbbq	r10, r8
        movq	[%rcx+344], r11
        movq	r11, [%rdx+360]
        movq	r8, [%rsp+360]
        sbbq	r11, r8
        movq	[%rcx+352], r10
        movq	r10, [%rdx+368]
        movq	r8, [%rsp+368]
        sbbq	r10, r8
        movq	[%rcx+360], r11
        movq	r11, [%rdx+376]
        movq	r8, [%rsp+376]
        sbbq	r11, r8
        movq	[%rcx+368], r10
        movq	[%rcx+376], r11
        sbbq	rax, 0
        addq	rsp, 384
        repz retq
sp_3072_cond_sub_48 ENDP
; /* Reduce the number back to 3072 bits using Montgomery reduction.
;  *
;  * a   A single precision number to reduce in place.
;  * m   The single precision number representing the modulus.
;  * mp  The digit representing the negative inverse of m mod 2^n.
;  */
sp_3072_mont_reduce_48 PROC
        movq	rcx, rdx
        movq	r9, rcx
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        xorq	rsi, rsi
        ; i = 0
        movq	r10, 48
        movq	r15, [%r9]
        movq	rdi, [%r9+8]
L_mont_loop_48:
        ; mu = a[i] * mp
        movq	r13, r15
        imulq	r13, r8
        ; a[i+0] += m[0] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx]
        addq	r15, rax
        adcq	r12, rdx
        ; a[i+1] += m[1] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+8]
        movq	r15, rdi
        addq	r15, rax
        adcq	r11, rdx
        addq	r15, r12
        adcq	r11, 0
        ; a[i+2] += m[2] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+16]
        movq	rdi, [%r9+16]
        addq	rdi, rax
        adcq	r12, rdx
        addq	rdi, r11
        adcq	r12, 0
        ; a[i+3] += m[3] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+24]
        movq	r14, [%r9+24]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+24], r14
        adcq	r11, 0
        ; a[i+4] += m[4] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+32]
        movq	r14, [%r9+32]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+32], r14
        adcq	r12, 0
        ; a[i+5] += m[5] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+40]
        movq	r14, [%r9+40]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+40], r14
        adcq	r11, 0
        ; a[i+6] += m[6] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+48]
        movq	r14, [%r9+48]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+48], r14
        adcq	r12, 0
        ; a[i+7] += m[7] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+56]
        movq	r14, [%r9+56]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+56], r14
        adcq	r11, 0
        ; a[i+8] += m[8] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+64]
        movq	r14, [%r9+64]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+64], r14
        adcq	r12, 0
        ; a[i+9] += m[9] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+72]
        movq	r14, [%r9+72]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+72], r14
        adcq	r11, 0
        ; a[i+10] += m[10] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+80]
        movq	r14, [%r9+80]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+80], r14
        adcq	r12, 0
        ; a[i+11] += m[11] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+88]
        movq	r14, [%r9+88]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+88], r14
        adcq	r11, 0
        ; a[i+12] += m[12] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+96]
        movq	r14, [%r9+96]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+96], r14
        adcq	r12, 0
        ; a[i+13] += m[13] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+104]
        movq	r14, [%r9+104]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+104], r14
        adcq	r11, 0
        ; a[i+14] += m[14] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+112]
        movq	r14, [%r9+112]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+112], r14
        adcq	r12, 0
        ; a[i+15] += m[15] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+120]
        movq	r14, [%r9+120]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+120], r14
        adcq	r11, 0
        ; a[i+16] += m[16] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+128]
        movq	r14, [%r9+128]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+128], r14
        adcq	r12, 0
        ; a[i+17] += m[17] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+136]
        movq	r14, [%r9+136]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+136], r14
        adcq	r11, 0
        ; a[i+18] += m[18] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+144]
        movq	r14, [%r9+144]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+144], r14
        adcq	r12, 0
        ; a[i+19] += m[19] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+152]
        movq	r14, [%r9+152]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+152], r14
        adcq	r11, 0
        ; a[i+20] += m[20] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+160]
        movq	r14, [%r9+160]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+160], r14
        adcq	r12, 0
        ; a[i+21] += m[21] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+168]
        movq	r14, [%r9+168]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+168], r14
        adcq	r11, 0
        ; a[i+22] += m[22] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+176]
        movq	r14, [%r9+176]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+176], r14
        adcq	r12, 0
        ; a[i+23] += m[23] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+184]
        movq	r14, [%r9+184]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+184], r14
        adcq	r11, 0
        ; a[i+24] += m[24] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+192]
        movq	r14, [%r9+192]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+192], r14
        adcq	r12, 0
        ; a[i+25] += m[25] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+200]
        movq	r14, [%r9+200]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+200], r14
        adcq	r11, 0
        ; a[i+26] += m[26] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+208]
        movq	r14, [%r9+208]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+208], r14
        adcq	r12, 0
        ; a[i+27] += m[27] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+216]
        movq	r14, [%r9+216]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+216], r14
        adcq	r11, 0
        ; a[i+28] += m[28] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+224]
        movq	r14, [%r9+224]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+224], r14
        adcq	r12, 0
        ; a[i+29] += m[29] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+232]
        movq	r14, [%r9+232]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+232], r14
        adcq	r11, 0
        ; a[i+30] += m[30] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+240]
        movq	r14, [%r9+240]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+240], r14
        adcq	r12, 0
        ; a[i+31] += m[31] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+248]
        movq	r14, [%r9+248]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+248], r14
        adcq	r11, 0
        ; a[i+32] += m[32] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+256]
        movq	r14, [%r9+256]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+256], r14
        adcq	r12, 0
        ; a[i+33] += m[33] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+264]
        movq	r14, [%r9+264]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+264], r14
        adcq	r11, 0
        ; a[i+34] += m[34] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+272]
        movq	r14, [%r9+272]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+272], r14
        adcq	r12, 0
        ; a[i+35] += m[35] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+280]
        movq	r14, [%r9+280]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+280], r14
        adcq	r11, 0
        ; a[i+36] += m[36] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+288]
        movq	r14, [%r9+288]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+288], r14
        adcq	r12, 0
        ; a[i+37] += m[37] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+296]
        movq	r14, [%r9+296]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+296], r14
        adcq	r11, 0
        ; a[i+38] += m[38] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+304]
        movq	r14, [%r9+304]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+304], r14
        adcq	r12, 0
        ; a[i+39] += m[39] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+312]
        movq	r14, [%r9+312]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+312], r14
        adcq	r11, 0
        ; a[i+40] += m[40] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+320]
        movq	r14, [%r9+320]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+320], r14
        adcq	r12, 0
        ; a[i+41] += m[41] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+328]
        movq	r14, [%r9+328]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+328], r14
        adcq	r11, 0
        ; a[i+42] += m[42] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+336]
        movq	r14, [%r9+336]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+336], r14
        adcq	r12, 0
        ; a[i+43] += m[43] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+344]
        movq	r14, [%r9+344]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+344], r14
        adcq	r11, 0
        ; a[i+44] += m[44] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+352]
        movq	r14, [%r9+352]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+352], r14
        adcq	r12, 0
        ; a[i+45] += m[45] * mu
        movq	rax, r13
        xorq	r11, r11
        mulq	[%rcx+360]
        movq	r14, [%r9+360]
        addq	r14, rax
        adcq	r11, rdx
        addq	r14, r12
        movq	[%r9+360], r14
        adcq	r11, 0
        ; a[i+46] += m[46] * mu
        movq	rax, r13
        xorq	r12, r12
        mulq	[%rcx+368]
        movq	r14, [%r9+368]
        addq	r14, rax
        adcq	r12, rdx
        addq	r14, r11
        movq	[%r9+368], r14
        adcq	r12, 0
        ; a[i+47] += m[47] * mu
        movq	rax, r13
        mulq	[%rcx+376]
        movq	r14, [%r9+376]
        addq	r12, rax
        adcq	rdx, rsi
        movq	rsi, 0
        adcq	rsi, 0
        addq	r14, r12
        movq	[%r9+376], r14
        adcq	[%r9+384], rdx
        adcq	rsi, 0
        ; i += 1
        addq	r9, 8
        decq	r10
        jnz	L_mont_loop_48
        movq	[%r9], r15
        movq	[%r9+8], rdi
        negq	rsi
        movq	r9, rsi
        movq	r8, rcx
        movq	rdx, r9
        movq	rcx, r9
        subq	rcx, 384
        callq	sp_3072_cond_sub_48
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        repz retq
sp_3072_mont_reduce_48 ENDP
IFDEF HAVE_INTEL_AVX2
; /* Mul a by digit b into r. (r = a * b)
;  *
;  * r  A single precision integer.
;  * a  A single precision integer.
;  * b  A single precision digit.
;  */
sp_3072_mul_d_avx2_48 PROC
        movq	rax, rdx
        push	r12
        push	r13
        ; A[0] * B
        movq	rdx, r8
        xorq	r13, r13
        mulxq	r12, r11, [%rax]
        movq	[%rcx], r11
        ; A[1] * B
        mulxq	r10, r9, [%rax+8]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+8], r12
        adoxq	r11, r10
        ; A[2] * B
        mulxq	r10, r9, [%rax+16]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+16], r11
        adoxq	r12, r10
        ; A[3] * B
        mulxq	r10, r9, [%rax+24]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+24], r12
        adoxq	r11, r10
        ; A[4] * B
        mulxq	r10, r9, [%rax+32]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+32], r11
        adoxq	r12, r10
        ; A[5] * B
        mulxq	r10, r9, [%rax+40]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+40], r12
        adoxq	r11, r10
        ; A[6] * B
        mulxq	r10, r9, [%rax+48]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+48], r11
        adoxq	r12, r10
        ; A[7] * B
        mulxq	r10, r9, [%rax+56]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+56], r12
        adoxq	r11, r10
        ; A[8] * B
        mulxq	r10, r9, [%rax+64]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+64], r11
        adoxq	r12, r10
        ; A[9] * B
        mulxq	r10, r9, [%rax+72]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+72], r12
        adoxq	r11, r10
        ; A[10] * B
        mulxq	r10, r9, [%rax+80]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+80], r11
        adoxq	r12, r10
        ; A[11] * B
        mulxq	r10, r9, [%rax+88]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+88], r12
        adoxq	r11, r10
        ; A[12] * B
        mulxq	r10, r9, [%rax+96]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+96], r11
        adoxq	r12, r10
        ; A[13] * B
        mulxq	r10, r9, [%rax+104]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+104], r12
        adoxq	r11, r10
        ; A[14] * B
        mulxq	r10, r9, [%rax+112]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+112], r11
        adoxq	r12, r10
        ; A[15] * B
        mulxq	r10, r9, [%rax+120]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+120], r12
        adoxq	r11, r10
        ; A[16] * B
        mulxq	r10, r9, [%rax+128]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+128], r11
        adoxq	r12, r10
        ; A[17] * B
        mulxq	r10, r9, [%rax+136]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+136], r12
        adoxq	r11, r10
        ; A[18] * B
        mulxq	r10, r9, [%rax+144]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+144], r11
        adoxq	r12, r10
        ; A[19] * B
        mulxq	r10, r9, [%rax+152]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+152], r12
        adoxq	r11, r10
        ; A[20] * B
        mulxq	r10, r9, [%rax+160]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+160], r11
        adoxq	r12, r10
        ; A[21] * B
        mulxq	r10, r9, [%rax+168]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+168], r12
        adoxq	r11, r10
        ; A[22] * B
        mulxq	r10, r9, [%rax+176]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+176], r11
        adoxq	r12, r10
        ; A[23] * B
        mulxq	r10, r9, [%rax+184]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+184], r12
        adoxq	r11, r10
        ; A[24] * B
        mulxq	r10, r9, [%rax+192]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+192], r11
        adoxq	r12, r10
        ; A[25] * B
        mulxq	r10, r9, [%rax+200]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+200], r12
        adoxq	r11, r10
        ; A[26] * B
        mulxq	r10, r9, [%rax+208]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+208], r11
        adoxq	r12, r10
        ; A[27] * B
        mulxq	r10, r9, [%rax+216]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+216], r12
        adoxq	r11, r10
        ; A[28] * B
        mulxq	r10, r9, [%rax+224]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+224], r11
        adoxq	r12, r10
        ; A[29] * B
        mulxq	r10, r9, [%rax+232]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+232], r12
        adoxq	r11, r10
        ; A[30] * B
        mulxq	r10, r9, [%rax+240]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+240], r11
        adoxq	r12, r10
        ; A[31] * B
        mulxq	r10, r9, [%rax+248]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+248], r12
        adoxq	r11, r10
        ; A[32] * B
        mulxq	r10, r9, [%rax+256]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+256], r11
        adoxq	r12, r10
        ; A[33] * B
        mulxq	r10, r9, [%rax+264]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+264], r12
        adoxq	r11, r10
        ; A[34] * B
        mulxq	r10, r9, [%rax+272]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+272], r11
        adoxq	r12, r10
        ; A[35] * B
        mulxq	r10, r9, [%rax+280]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+280], r12
        adoxq	r11, r10
        ; A[36] * B
        mulxq	r10, r9, [%rax+288]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+288], r11
        adoxq	r12, r10
        ; A[37] * B
        mulxq	r10, r9, [%rax+296]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+296], r12
        adoxq	r11, r10
        ; A[38] * B
        mulxq	r10, r9, [%rax+304]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+304], r11
        adoxq	r12, r10
        ; A[39] * B
        mulxq	r10, r9, [%rax+312]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+312], r12
        adoxq	r11, r10
        ; A[40] * B
        mulxq	r10, r9, [%rax+320]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+320], r11
        adoxq	r12, r10
        ; A[41] * B
        mulxq	r10, r9, [%rax+328]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+328], r12
        adoxq	r11, r10
        ; A[42] * B
        mulxq	r10, r9, [%rax+336]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+336], r11
        adoxq	r12, r10
        ; A[43] * B
        mulxq	r10, r9, [%rax+344]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+344], r12
        adoxq	r11, r10
        ; A[44] * B
        mulxq	r10, r9, [%rax+352]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+352], r11
        adoxq	r12, r10
        ; A[45] * B
        mulxq	r10, r9, [%rax+360]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+360], r12
        adoxq	r11, r10
        ; A[46] * B
        mulxq	r10, r9, [%rax+368]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+368], r11
        adoxq	r12, r10
        ; A[47] * B
        mulxq	r10, r9, [%rax+376]
        movq	r11, r13
        adcxq	r12, r9
        adoxq	r11, r10
        adcxq	r11, r13
        movq	[%rcx+376], r12
        movq	[%rcx+384], r11
        pop	r13
        pop	r12
        repz retq
sp_3072_mul_d_avx2_48 ENDP
ENDIF
; /* Compare a with b in constant time.
;  *
;  * a  A single precision integer.
;  * b  A single precision integer.
;  * return -ve, 0 or +ve if a is less than, equal to or greater than b
;  * respectively.
;  */
sp_3072_cmp_48 PROC
        push	r12
        xorq	r9, r9
        movq	r8, -1
        movq	rax, -1
        movq	r10, 1
        movq	r11, [%rcx+376]
        movq	r12, [%rdx+376]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+368]
        movq	r12, [%rdx+368]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+360]
        movq	r12, [%rdx+360]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+352]
        movq	r12, [%rdx+352]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+344]
        movq	r12, [%rdx+344]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+336]
        movq	r12, [%rdx+336]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+328]
        movq	r12, [%rdx+328]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+320]
        movq	r12, [%rdx+320]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+312]
        movq	r12, [%rdx+312]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+304]
        movq	r12, [%rdx+304]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+296]
        movq	r12, [%rdx+296]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+288]
        movq	r12, [%rdx+288]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+280]
        movq	r12, [%rdx+280]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+272]
        movq	r12, [%rdx+272]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+264]
        movq	r12, [%rdx+264]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+256]
        movq	r12, [%rdx+256]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+248]
        movq	r12, [%rdx+248]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+240]
        movq	r12, [%rdx+240]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+232]
        movq	r12, [%rdx+232]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+224]
        movq	r12, [%rdx+224]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+216]
        movq	r12, [%rdx+216]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+208]
        movq	r12, [%rdx+208]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+200]
        movq	r12, [%rdx+200]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+192]
        movq	r12, [%rdx+192]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+184]
        movq	r12, [%rdx+184]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+176]
        movq	r12, [%rdx+176]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+168]
        movq	r12, [%rdx+168]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+160]
        movq	r12, [%rdx+160]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+152]
        movq	r12, [%rdx+152]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+144]
        movq	r12, [%rdx+144]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+136]
        movq	r12, [%rdx+136]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+128]
        movq	r12, [%rdx+128]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+120]
        movq	r12, [%rdx+120]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+112]
        movq	r12, [%rdx+112]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+104]
        movq	r12, [%rdx+104]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+96]
        movq	r12, [%rdx+96]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+88]
        movq	r12, [%rdx+88]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+80]
        movq	r12, [%rdx+80]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+72]
        movq	r12, [%rdx+72]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+64]
        movq	r12, [%rdx+64]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+56]
        movq	r12, [%rdx+56]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+48]
        movq	r12, [%rdx+48]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+40]
        movq	r12, [%rdx+40]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+32]
        movq	r12, [%rdx+32]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+24]
        movq	r12, [%rdx+24]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+16]
        movq	r12, [%rdx+16]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+8]
        movq	r12, [%rdx+8]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx]
        movq	r12, [%rdx]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        xorq	rax, r8
        pop	r12
        repz retq
sp_3072_cmp_48 ENDP
IFDEF HAVE_INTEL_AVX2
; /* Reduce the number back to 3072 bits using Montgomery reduction.
;  *
;  * a   A single precision number to reduce in place.
;  * m   The single precision number representing the modulus.
;  * mp  The digit representing the negative inverse of m mod 2^n.
;  */
sp_3072_mont_reduce_avx2_48 PROC
        movq	rax, rdx
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        xorq	rdi, rdi
        ; i = 0
        movq	r11, 48
        movq	r15, [%rcx]
        xorq	r14, r14
L_mont_loop_avx2_48:
        ; mu = a[i] * mp
        movq	rdx, r15
        mulxq	r10, rdx, r8
        movq	r12, r15
        ; a[i+0] += m[0] * mu
        mulxq	r10, r9, [%rax]
        movq	r15, [%rcx+8]
        adcxq	r12, r9
        adoxq	r15, r10
        ; a[i+1] += m[1] * mu
        mulxq	r10, r9, [%rax+8]
        movq	r12, [%rcx+16]
        adcxq	r15, r9
        adoxq	r12, r10
        ; a[i+2] += m[2] * mu
        mulxq	r10, r9, [%rax+16]
        movq	r13, [%rcx+24]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+16], r12
        ; a[i+3] += m[3] * mu
        mulxq	r10, r9, [%rax+24]
        movq	r12, [%rcx+32]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+24], r13
        ; a[i+4] += m[4] * mu
        mulxq	r10, r9, [%rax+32]
        movq	r13, [%rcx+40]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+32], r12
        ; a[i+5] += m[5] * mu
        mulxq	r10, r9, [%rax+40]
        movq	r12, [%rcx+48]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+40], r13
        ; a[i+6] += m[6] * mu
        mulxq	r10, r9, [%rax+48]
        movq	r13, [%rcx+56]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+48], r12
        ; a[i+7] += m[7] * mu
        mulxq	r10, r9, [%rax+56]
        movq	r12, [%rcx+64]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+56], r13
        ; a[i+8] += m[8] * mu
        mulxq	r10, r9, [%rax+64]
        movq	r13, [%rcx+72]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+64], r12
        ; a[i+9] += m[9] * mu
        mulxq	r10, r9, [%rax+72]
        movq	r12, [%rcx+80]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+72], r13
        ; a[i+10] += m[10] * mu
        mulxq	r10, r9, [%rax+80]
        movq	r13, [%rcx+88]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+80], r12
        ; a[i+11] += m[11] * mu
        mulxq	r10, r9, [%rax+88]
        movq	r12, [%rcx+96]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+88], r13
        ; a[i+12] += m[12] * mu
        mulxq	r10, r9, [%rax+96]
        movq	r13, [%rcx+104]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+96], r12
        ; a[i+13] += m[13] * mu
        mulxq	r10, r9, [%rax+104]
        movq	r12, [%rcx+112]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+104], r13
        ; a[i+14] += m[14] * mu
        mulxq	r10, r9, [%rax+112]
        movq	r13, [%rcx+120]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+112], r12
        ; a[i+15] += m[15] * mu
        mulxq	r10, r9, [%rax+120]
        movq	r12, [%rcx+128]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+120], r13
        ; a[i+16] += m[16] * mu
        mulxq	r10, r9, [%rax+128]
        movq	r13, [%rcx+136]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+128], r12
        ; a[i+17] += m[17] * mu
        mulxq	r10, r9, [%rax+136]
        movq	r12, [%rcx+144]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+136], r13
        ; a[i+18] += m[18] * mu
        mulxq	r10, r9, [%rax+144]
        movq	r13, [%rcx+152]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+144], r12
        ; a[i+19] += m[19] * mu
        mulxq	r10, r9, [%rax+152]
        movq	r12, [%rcx+160]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+152], r13
        ; a[i+20] += m[20] * mu
        mulxq	r10, r9, [%rax+160]
        movq	r13, [%rcx+168]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+160], r12
        ; a[i+21] += m[21] * mu
        mulxq	r10, r9, [%rax+168]
        movq	r12, [%rcx+176]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+168], r13
        ; a[i+22] += m[22] * mu
        mulxq	r10, r9, [%rax+176]
        movq	r13, [%rcx+184]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+176], r12
        ; a[i+23] += m[23] * mu
        mulxq	r10, r9, [%rax+184]
        movq	r12, [%rcx+192]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+184], r13
        ; a[i+24] += m[24] * mu
        mulxq	r10, r9, [%rax+192]
        movq	r13, [%rcx+200]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+192], r12
        ; a[i+25] += m[25] * mu
        mulxq	r10, r9, [%rax+200]
        movq	r12, [%rcx+208]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+200], r13
        ; a[i+26] += m[26] * mu
        mulxq	r10, r9, [%rax+208]
        movq	r13, [%rcx+216]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+208], r12
        ; a[i+27] += m[27] * mu
        mulxq	r10, r9, [%rax+216]
        movq	r12, [%rcx+224]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+216], r13
        ; a[i+28] += m[28] * mu
        mulxq	r10, r9, [%rax+224]
        movq	r13, [%rcx+232]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+224], r12
        ; a[i+29] += m[29] * mu
        mulxq	r10, r9, [%rax+232]
        movq	r12, [%rcx+240]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+232], r13
        ; a[i+30] += m[30] * mu
        mulxq	r10, r9, [%rax+240]
        movq	r13, [%rcx+248]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+240], r12
        ; a[i+31] += m[31] * mu
        mulxq	r10, r9, [%rax+248]
        movq	r12, [%rcx+256]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+248], r13
        ; a[i+32] += m[32] * mu
        mulxq	r10, r9, [%rax+256]
        movq	r13, [%rcx+264]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+256], r12
        ; a[i+33] += m[33] * mu
        mulxq	r10, r9, [%rax+264]
        movq	r12, [%rcx+272]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+264], r13
        ; a[i+34] += m[34] * mu
        mulxq	r10, r9, [%rax+272]
        movq	r13, [%rcx+280]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+272], r12
        ; a[i+35] += m[35] * mu
        mulxq	r10, r9, [%rax+280]
        movq	r12, [%rcx+288]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+280], r13
        ; a[i+36] += m[36] * mu
        mulxq	r10, r9, [%rax+288]
        movq	r13, [%rcx+296]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+288], r12
        ; a[i+37] += m[37] * mu
        mulxq	r10, r9, [%rax+296]
        movq	r12, [%rcx+304]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+296], r13
        ; a[i+38] += m[38] * mu
        mulxq	r10, r9, [%rax+304]
        movq	r13, [%rcx+312]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+304], r12
        ; a[i+39] += m[39] * mu
        mulxq	r10, r9, [%rax+312]
        movq	r12, [%rcx+320]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+312], r13
        ; a[i+40] += m[40] * mu
        mulxq	r10, r9, [%rax+320]
        movq	r13, [%rcx+328]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+320], r12
        ; a[i+41] += m[41] * mu
        mulxq	r10, r9, [%rax+328]
        movq	r12, [%rcx+336]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+328], r13
        ; a[i+42] += m[42] * mu
        mulxq	r10, r9, [%rax+336]
        movq	r13, [%rcx+344]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+336], r12
        ; a[i+43] += m[43] * mu
        mulxq	r10, r9, [%rax+344]
        movq	r12, [%rcx+352]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+344], r13
        ; a[i+44] += m[44] * mu
        mulxq	r10, r9, [%rax+352]
        movq	r13, [%rcx+360]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+352], r12
        ; a[i+45] += m[45] * mu
        mulxq	r10, r9, [%rax+360]
        movq	r12, [%rcx+368]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+360], r13
        ; a[i+46] += m[46] * mu
        mulxq	r10, r9, [%rax+368]
        movq	r13, [%rcx+376]
        adcxq	r12, r9
        adoxq	r13, r10
        movq	[%rcx+368], r12
        ; a[i+47] += m[47] * mu
        mulxq	r10, r9, [%rax+376]
        movq	r12, [%rcx+384]
        adcxq	r13, r9
        adoxq	r12, r10
        movq	[%rcx+376], r13
        adcxq	r12, rdi
        movq	rdi, r14
        adoxq	rdi, r14
        adcxq	rdi, r14
        movq	[%rcx+384], r12
        ; i += 1
        addq	rcx, 8
        decq	r11
        jnz	L_mont_loop_avx2_48
        movq	[%rcx], r15
        negq	rdi
        movq	r9, rdi
        movq	r8, rax
        movq	rdx, rcx
        movq	rcx, rcx
        subq	rcx, 384
        callq	sp_3072_cond_sub_48
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        repz retq
sp_3072_mont_reduce_avx2_48 ENDP
ENDIF
; /* Shift number left by n bit. (r = a << n)
;  *
;  * r  Result of left shift by n.
;  * a  Number to shift.
;  * n  Amoutnt o shift.
;  */
sp_3072_lshift_48 PROC
        movq	rcx, r8
        push	r12
        movq	r11, 0
        movq	r12, [%rdx+344]
        movq	rax, [%rdx+352]
        movq	r8, [%rdx+360]
        movq	r9, [%rdx+368]
        movq	r10, [%rdx+376]
        shldq	r11, r10, cl
        shldq	r10, r9, cl
        shldq	r9, r8, cl
        shldq	r8, rax, cl
        shldq	rax, r12, cl
        movq	[%rcx+352], rax
        movq	[%rcx+360], r8
        movq	[%rcx+368], r9
        movq	[%rcx+376], r10
        movq	[%rcx+384], r11
        movq	r10, [%rdx+312]
        movq	rax, [%rdx+320]
        movq	r8, [%rdx+328]
        movq	r9, [%rdx+336]
        shldq	r12, r9, cl
        shldq	r9, r8, cl
        shldq	r8, rax, cl
        shldq	rax, r10, cl
        movq	[%rcx+320], rax
        movq	[%rcx+328], r8
        movq	[%rcx+336], r9
        movq	[%rcx+344], r12
        movq	r12, [%rdx+280]
        movq	rax, [%rdx+288]
        movq	r8, [%rdx+296]
        movq	r9, [%rdx+304]
        shldq	r10, r9, cl
        shldq	r9, r8, cl
        shldq	r8, rax, cl
        shldq	rax, r12, cl
        movq	[%rcx+288], rax
        movq	[%rcx+296], r8
        movq	[%rcx+304], r9
        movq	[%rcx+312], r10
        movq	r10, [%rdx+248]
        movq	rax, [%rdx+256]
        movq	r8, [%rdx+264]
        movq	r9, [%rdx+272]
        shldq	r12, r9, cl
        shldq	r9, r8, cl
        shldq	r8, rax, cl
        shldq	rax, r10, cl
        movq	[%rcx+256], rax
        movq	[%rcx+264], r8
        movq	[%rcx+272], r9
        movq	[%rcx+280], r12
        movq	r12, [%rdx+216]
        movq	rax, [%rdx+224]
        movq	r8, [%rdx+232]
        movq	r9, [%rdx+240]
        shldq	r10, r9, cl
        shldq	r9, r8, cl
        shldq	r8, rax, cl
        shldq	rax, r12, cl
        movq	[%rcx+224], rax
        movq	[%rcx+232], r8
        movq	[%rcx+240], r9
        movq	[%rcx+248], r10
        movq	r10, [%rdx+184]
        movq	rax, [%rdx+192]
        movq	r8, [%rdx+200]
        movq	r9, [%rdx+208]
        shldq	r12, r9, cl
        shldq	r9, r8, cl
        shldq	r8, rax, cl
        shldq	rax, r10, cl
        movq	[%rcx+192], rax
        movq	[%rcx+200], r8
        movq	[%rcx+208], r9
        movq	[%rcx+216], r12
        movq	r12, [%rdx+152]
        movq	rax, [%rdx+160]
        movq	r8, [%rdx+168]
        movq	r9, [%rdx+176]
        shldq	r10, r9, cl
        shldq	r9, r8, cl
        shldq	r8, rax, cl
        shldq	rax, r12, cl
        movq	[%rcx+160], rax
        movq	[%rcx+168], r8
        movq	[%rcx+176], r9
        movq	[%rcx+184], r10
        movq	r10, [%rdx+120]
        movq	rax, [%rdx+128]
        movq	r8, [%rdx+136]
        movq	r9, [%rdx+144]
        shldq	r12, r9, cl
        shldq	r9, r8, cl
        shldq	r8, rax, cl
        shldq	rax, r10, cl
        movq	[%rcx+128], rax
        movq	[%rcx+136], r8
        movq	[%rcx+144], r9
        movq	[%rcx+152], r12
        movq	r12, [%rdx+88]
        movq	rax, [%rdx+96]
        movq	r8, [%rdx+104]
        movq	r9, [%rdx+112]
        shldq	r10, r9, cl
        shldq	r9, r8, cl
        shldq	r8, rax, cl
        shldq	rax, r12, cl
        movq	[%rcx+96], rax
        movq	[%rcx+104], r8
        movq	[%rcx+112], r9
        movq	[%rcx+120], r10
        movq	r10, [%rdx+56]
        movq	rax, [%rdx+64]
        movq	r8, [%rdx+72]
        movq	r9, [%rdx+80]
        shldq	r12, r9, cl
        shldq	r9, r8, cl
        shldq	r8, rax, cl
        shldq	rax, r10, cl
        movq	[%rcx+64], rax
        movq	[%rcx+72], r8
        movq	[%rcx+80], r9
        movq	[%rcx+88], r12
        movq	r12, [%rdx+24]
        movq	rax, [%rdx+32]
        movq	r8, [%rdx+40]
        movq	r9, [%rdx+48]
        shldq	r10, r9, cl
        shldq	r9, r8, cl
        shldq	r8, rax, cl
        shldq	rax, r12, cl
        movq	[%rcx+32], rax
        movq	[%rcx+40], r8
        movq	[%rcx+48], r9
        movq	[%rcx+56], r10
        movq	rax, [%rdx]
        movq	r8, [%rdx+8]
        movq	r9, [%rdx+16]
        shldq	r12, r9, cl
        shldq	r9, r8, cl
        shldq	r8, rax, cl
        shlq	rax, cl
        movq	[%rcx], rax
        movq	[%rcx+8], r8
        movq	[%rcx+16], r9
        movq	[%rcx+24], r12
        pop	r12
        repz retq
; /* Conditionally copy a into r using the mask m.
;  * m is -1 to copy and 0 when not.
;  *
;  * r  A single precision number to copy over.
;  * a  A single precision number to copy.
;  * m  Mask value to apply.
;  */
sp_256_cond_copy_4 PROC
        movq	rax, [%rcx]
        movq	r9, [%rcx+8]
        movq	r10, [%rcx+16]
        movq	r11, [%rcx+24]
        xorq	rax, [%rdx]
        xorq	r9, [%rdx+8]
        xorq	r10, [%rdx+16]
        xorq	r11, [%rdx+24]
        andq	rax, r8
        andq	r9, r8
        andq	r10, r8
        andq	r11, r8
        xorq	[%rcx], rax
        xorq	[%rcx+8], r9
        xorq	[%rcx+16], r10
        xorq	[%rcx+24], r11
        repz retq
sp_256_cond_copy_4 ENDP
; /* Compare a with b in constant time.
;  *
;  * a  A single precision integer.
;  * b  A single precision integer.
;  * return -ve, 0 or +ve if a is less than, equal to or greater than b
;  * respectively.
;  */
sp_256_cmp_4 PROC
        push	r12
        xorq	r9, r9
        movq	r8, -1
        movq	rax, -1
        movq	r10, 1
        movq	r11, [%rcx+24]
        movq	r12, [%rdx+24]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+16]
        movq	r12, [%rdx+16]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx+8]
        movq	r12, [%rdx+8]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        movq	r11, [%rcx]
        movq	r12, [%rdx]
        andq	r11, r8
        andq	r12, r8
        subq	r11, r12
        cmova	rax, r10
        cmovc	rax, r8
        cmovnz	r8, r9
        xorq	rax, r8
        pop	r12
        repz retq
sp_256_cmp_4 ENDP
; /* Conditionally subtract b from a using the mask m.
;  * m is -1 to subtract and 0 when not copying.
;  *
;  * r  A single precision number representing condition subtract result.
;  * a  A single precision number to subtract from.
;  * b  A single precision number to subtract.
;  * m  Mask value to apply.
;  */
sp_256_cond_sub_4 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        movq	rax, 0
        movq	r14, [%r8]
        movq	r15, [%r8+8]
        movq	rdi, [%r8+16]
        movq	rsi, [%r8+24]
        andq	r14, r9
        andq	r15, r9
        andq	rdi, r9
        andq	rsi, r9
        movq	r10, [%rdx]
        movq	r11, [%rdx+8]
        movq	r12, [%rdx+16]
        movq	r13, [%rdx+24]
        subq	r10, r14
        sbbq	r11, r15
        sbbq	r12, rdi
        sbbq	r13, rsi
        movq	[%rcx], r10
        movq	[%rcx+8], r11
        movq	[%rcx+16], r12
        movq	[%rcx+24], r13
        sbbq	rax, 0
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        repz retq
sp_256_cond_sub_4 ENDP
; /* Sub b from a into r. (r = a - b)
;  *
;  * r  A single precision integer.
;  * a  A single precision integer.
;  * b  A single precision integer.
;  */
sp_256_sub_4 PROC
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        xorq	rax, rax
        movq	r10, [%rdx]
        movq	r11, [%rdx+8]
        movq	r12, [%rdx+16]
        movq	r13, [%rdx+24]
        movq	r14, [%r8]
        movq	r15, [%r8+8]
        movq	rdi, [%r8+16]
        movq	rsi, [%r8+24]
        subq	r10, r14
        sbbq	r11, r15
        sbbq	r12, rdi
        sbbq	r13, rsi
        movq	[%rcx], r10
        movq	[%rcx+8], r11
        movq	[%rcx+16], r12
        movq	[%rcx+24], r13
        sbbq	rax, 0
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        repz retq
sp_256_sub_4 ENDP
; /* Reduce the number back to 256 bits using Montgomery reduction.
;  *
;  * a   A single precision number to reduce in place.
;  * m   The single precision number representing the modulus.
;  * mp  The digit representing the negative inverse of m mod 2^n.
;  */
sp_256_mont_reduce_4 PROC
        movq	rcx, rdx
        movq	r9, rcx
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        ; i = 0
        xorq	rdi, rdi
        movq	r10, 4
        movq	r15, r9
L_mont_loop_4:
        ; mu = a[i] * mp
        movq	r14, [%r15]
        imulq	r14, r8
        ; a[i+0] += m[0] * mu
        movq	rax, [%rcx]
        movq	r12, [%rcx+8]
        mulq	r14
        movq	rsi, [%r15]
        addq	rsi, rax
        movq	r11, rdx
        movq	[%r15], rsi
        adcq	r11, 0
        ; a[i+1] += m[1] * mu
        movq	rax, r12
        mulq	r14
        movq	r12, [%rcx+16]
        movq	rsi, [%r15+8]
        addq	rax, r11
        movq	r13, rdx
        adcq	r13, 0
        addq	rsi, rax
        movq	[%r15+8], rsi
        adcq	r13, 0
        ; a[i+2] += m[2] * mu
        movq	rax, r12
        mulq	r14
        movq	r12, [%rcx+24]
        movq	rsi, [%r15+16]
        addq	rax, r13
        movq	r11, rdx
        adcq	r11, 0
        addq	rsi, rax
        movq	[%r15+16], rsi
        adcq	r11, 0
        ; a[i+3] += m[3] * mu
        movq	rax, r12
        mulq	r14
        movq	rsi, [%r15+24]
        addq	rax, r11
        adcq	rdx, rdi
        movq	rdi, 0
        adcq	rdi, 0
        addq	rsi, rax
        movq	[%r15+24], rsi
        adcq	[%r15+32], rdx
        adcq	rdi, 0
        ; i += 1
        addq	r15, 8
        decq	r10
        jnz	L_mont_loop_4
        xorq	rax, rax
        movq	rdx, [%r9+32]
        movq	r10, [%r9+40]
        movq	rsi, [%r9+48]
        movq	r11, [%r9+56]
        subq	rax, rdi
        movq	r12, [%rcx]
        movq	r13, [%rcx+8]
        movq	r14, [%rcx+16]
        movq	r15, [%rcx+24]
        andq	r12, rax
        andq	r13, rax
        andq	r14, rax
        andq	r15, rax
        subq	rdx, r12
        sbbq	r10, r13
        sbbq	rsi, r14
        sbbq	r11, r15
        movq	[%r9], rdx
        movq	[%r9+8], r10
        movq	[%r9+16], rsi
        movq	[%r9+24], r11
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        repz retq
sp_256_mont_reduce_4 ENDP
; /* Multiply two Montogmery form numbers mod the modulus (prime).
;  * (r = a * b mod m)
;  *
;  * r   Result of multiplication.
;  * a   First number to multiply in Montogmery form.
;  * b   Second number to multiply in Montogmery form.
;  * m   Modulus (prime).
;  * mp  Montogmery mulitplier.
;  */
sp_256_mont_mul_4 PROC
        movq	rcx, rdx
        movq	r10, rcx
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        ;  A[0] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx]
        movq	r11, rax
        movq	r12, rdx
        ;  A[0] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx]
        xorq	r13, r13
        addq	r12, rax
        adcq	r13, rdx
        ;  A[1] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+8]
        xorq	r14, r14
        addq	r12, rax
        adcq	r13, rdx
        adcq	r14, 0
        ;  A[0] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx]
        addq	r13, rax
        adcq	r14, rdx
        ;  A[1] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+8]
        xorq	r15, r15
        addq	r13, rax
        adcq	r14, rdx
        adcq	r15, 0
        ;  A[2] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+16]
        addq	r13, rax
        adcq	r14, rdx
        adcq	r15, 0
        ;  A[0] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx]
        xorq	rdi, rdi
        addq	r14, rax
        adcq	r15, rdx
        adcq	rdi, 0
        ;  A[1] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+8]
        addq	r14, rax
        adcq	r15, rdx
        adcq	rdi, 0
        ;  A[2] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+16]
        addq	r14, rax
        adcq	r15, rdx
        adcq	rdi, 0
        ;  A[3] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+24]
        addq	r14, rax
        adcq	r15, rdx
        adcq	rdi, 0
        ;  A[1] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+8]
        xorq	rsi, rsi
        addq	r15, rax
        adcq	rdi, rdx
        adcq	rsi, 0
        ;  A[2] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+16]
        addq	r15, rax
        adcq	rdi, rdx
        adcq	rsi, 0
        ;  A[3] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+24]
        addq	r15, rax
        adcq	rdi, rdx
        adcq	rsi, 0
        ;  A[2] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+16]
        xorq	rbx, rbx
        addq	rdi, rax
        adcq	rsi, rdx
        adcq	rbx, 0
        ;  A[3] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+24]
        addq	rdi, rax
        adcq	rsi, rdx
        adcq	rbx, 0
        ;  A[3] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+24]
        addq	rsi, rax
        adcq	rbx, rdx
        ; Start Reduction
        ; mu = a[0]-a[3] + a[0]-a[2] << 32 << 64 + (a[0] * 2) << 192
        ;    - a[0] << 32 << 192
        ;   + (a[0] * 2) << 192
        movq	rax, r11
        movq	rdx, r14
        addq	rdx, r11
        movq	rcx, r12
        addq	rdx, r11
        movq	r8, r13
        ;   a[0]-a[2] << 32
        shlq	r11, 32
        shldq	r13, rcx, 32
        shldq	r12, rax, 32
        ;   - a[0] << 32 << 192
        subq	rdx, r11
        ;   + a[0]-a[2] << 32 << 64
        addq	rcx, r11
        adcq	r8, r12
        adcq	rdx, r13
        ; a += (mu << 256) - (mu << 224) + (mu << 192) + (mu << 96) - mu
        ;   a += mu << 256
        xorq	r11, r11
        addq	r15, rax
        adcq	rdi, rcx
        adcq	rsi, r8
        adcq	rbx, rdx
        sbbq	r11, 0
        ;   a += mu << 192
        addq	r14, rax
        adcq	r15, rcx
        adcq	rdi, r8
        adcq	rsi, rdx
        adcq	rbx, 0
        sbbq	r11, 0
        ; mu <<= 32
        movq	r9, rdx
        shldq	rdx, r8, 32
        shldq	r8, rcx, 32
        shldq	rcx, rax, 32
        shrq	r9, 32
        shlq	rax, 32
        ;   a += (mu << 32) << 64
        addq	r14, r8
        adcq	r15, rdx
        adcq	rdi, r9
        adcq	rsi, 0
        adcq	rbx, 0
        sbbq	r11, 0
        ;   a -= (mu << 32) << 192
        subq	r14, rax
        movq	rax, 4294967295
        sbbq	r15, rcx
        movq	rcx, 18446744069414584321
        sbbq	rdi, r8
        sbbq	rsi, rdx
        sbbq	rbx, r9
        adcq	r11, 0
        ; mask m and sub from result if overflow
        ;  m[0] = -1 & mask = mask
        andq	rax, r11
        ;  m[2] =  0 & mask = 0
        andq	rcx, r11
        subq	r15, r11
        sbbq	rdi, rax
        sbbq	rsi, 0
        sbbq	rbx, rcx
        movq	[%r10], r15
        movq	[%r10+8], rdi
        movq	[%r10+16], rsi
        movq	[%r10+24], rbx
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        repz retq
sp_256_mont_mul_4 ENDP
; /* Square the Montgomery form number mod the modulus (prime). (r = a * a mod m)
;  *
;  * r   Result of squaring.
;  * a   Number to square in Montogmery form.
;  * m   Modulus (prime).
;  * mp  Montogmery mulitplier.
;  */
sp_256_mont_sqr_4 PROC
        movq	rcx, rdx
        movq	r8, rcx
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        ;  A[0] * A[1]
        movq	rax, [%rcx]
        mulq	[%rcx+8]
        movq	r12, rax
        movq	r13, rdx
        ;  A[0] * A[2]
        movq	rax, [%rcx]
        mulq	[%rcx+16]
        xorq	r14, r14
        addq	r13, rax
        adcq	r14, rdx
        ;  A[0] * A[3]
        movq	rax, [%rcx]
        mulq	[%rcx+24]
        xorq	r15, r15
        addq	r14, rax
        adcq	r15, rdx
        ;  A[1] * A[2]
        movq	rax, [%rcx+8]
        mulq	[%rcx+16]
        xorq	rdi, rdi
        addq	r14, rax
        adcq	r15, rdx
        adcq	rdi, 0
        ;  A[1] * A[3]
        movq	rax, [%rcx+8]
        mulq	[%rcx+24]
        addq	r15, rax
        adcq	rdi, rdx
        ;  A[2] * A[3]
        movq	rax, [%rcx+16]
        mulq	[%rcx+24]
        xorq	rsi, rsi
        addq	rdi, rax
        adcq	rsi, rdx
        ; Double
        xorq	rbx, rbx
        addq	r12, r12
        adcq	r13, r13
        adcq	r14, r14
        adcq	r15, r15
        adcq	rdi, rdi
        adcq	rsi, rsi
        adcq	rbx, 0
        ;  A[0] * A[0]
        movq	rax, [%rcx]
        mulq	rax
        movq	rax, rax
        movq	rdx, rdx
        movq	r11, rax
        movq	r10, rdx
        ;  A[1] * A[1]
        movq	rax, [%rcx+8]
        mulq	rax
        movq	rax, rax
        movq	rdx, rdx
        addq	r12, r10
        adcq	r13, rax
        adcq	rdx, 0
        movq	r10, rdx
        ;  A[2] * A[2]
        movq	rax, [%rcx+16]
        mulq	rax
        movq	rax, rax
        movq	rdx, rdx
        addq	r14, r10
        adcq	r15, rax
        adcq	rdx, 0
        movq	r10, rdx
        ;  A[3] * A[3]
        movq	rax, [%rcx+24]
        mulq	rax
        addq	rsi, rax
        adcq	rbx, rdx
        addq	rdi, r10
        adcq	rsi, 0
        adcq	rbx, 0
        ; Start Reduction
        ; mu = a[0]-a[3] + a[0]-a[2] << 32 << 64 + (a[0] * 2) << 192
        ;    - a[0] << 32 << 192
        ;   + (a[0] * 2) << 192
        movq	rax, r11
        movq	rdx, r14
        addq	rdx, r11
        movq	rcx, r12
        addq	rdx, r11
        movq	r10, r13
        ;   a[0]-a[2] << 32
        shlq	r11, 32
        shldq	r13, rcx, 32
        shldq	r12, rax, 32
        ;   - a[0] << 32 << 192
        subq	rdx, r11
        ;   + a[0]-a[2] << 32 << 64
        addq	rcx, r11
        adcq	r10, r12
        adcq	rdx, r13
        ; a += (mu << 256) - (mu << 224) + (mu << 192) + (mu << 96) - mu
        ;   a += mu << 256
        xorq	r11, r11
        addq	r15, rax
        adcq	rdi, rcx
        adcq	rsi, r10
        adcq	rbx, rdx
        sbbq	r11, 0
        ;   a += mu << 192
        addq	r14, rax
        adcq	r15, rcx
        adcq	rdi, r10
        adcq	rsi, rdx
        adcq	rbx, 0
        sbbq	r11, 0
        ; mu <<= 32
        movq	r9, rdx
        shldq	rdx, r10, 32
        shldq	r10, rcx, 32
        shldq	rcx, rax, 32
        shrq	r9, 32
        shlq	rax, 32
        ;   a += (mu << 32) << 64
        addq	r14, r10
        adcq	r15, rdx
        adcq	rdi, r9
        adcq	rsi, 0
        adcq	rbx, 0
        sbbq	r11, 0
        ;   a -= (mu << 32) << 192
        subq	r14, rax
        movq	rax, 4294967295
        sbbq	r15, rcx
        movq	rcx, 18446744069414584321
        sbbq	rdi, r10
        sbbq	rsi, rdx
        sbbq	rbx, r9
        adcq	r11, 0
        ; mask m and sub from result if overflow
        ;  m[0] = -1 & mask = mask
        andq	rax, r11
        ;  m[2] =  0 & mask = 0
        andq	rcx, r11
        subq	r15, r11
        sbbq	rdi, rax
        sbbq	rsi, 0
        sbbq	rbx, rcx
        movq	[%r8], r15
        movq	[%r8+8], rdi
        movq	[%r8+16], rsi
        movq	[%r8+24], rbx
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        repz retq
sp_256_mont_sqr_4 ENDP
; /* Add two Montgomery form numbers (r = a + b % m).
;  *
;  * r   Result of addition.
;  * a   First number to add in Montogmery form.
;  * b   Second number to add in Montogmery form.
;  * m   Modulus (prime).
;  */
sp_256_mont_add_4 PROC
        push	r12
        push	r13
        movq	rax, [%rdx]
        movq	r9, [%rdx+8]
        movq	r10, [%rdx+16]
        movq	r11, [%rdx+24]
        addq	rax, [%r8]
        adcq	r9, [%r8+8]
        movq	r12, 4294967295
        adcq	r10, [%r8+16]
        movq	r13, 18446744069414584321
        adcq	r11, [%r8+24]
        movq	r8, 0
        sbbq	r8, 0
        andq	r12, r8
        andq	r13, r8
        subq	rax, r8
        sbbq	r9, r12
        movq	[%rcx], rax
        sbbq	r10, 0
        movq	[%rcx+8], r9
        sbbq	r11, r13
        movq	[%rcx+16], r10
        movq	[%rcx+24], r11
        pop	r13
        pop	r12
        repz retq
sp_256_mont_add_4 ENDP
; /* Double a Montgomery form number (r = a + a % m).
;  *
;  * r   Result of doubling.
;  * a   Number to double in Montogmery form.
;  * m   Modulus (prime).
;  */
sp_256_mont_dbl_4 PROC
        push	r12
        push	r13
        movq	rax, [%rdx]
        movq	r8, [%rdx+8]
        movq	r9, [%rdx+16]
        movq	r10, [%rdx+24]
        xorq	r13, r13
        addq	rax, rax
        adcq	r8, r8
        movq	r11, 4294967295
        adcq	r9, r9
        adcq	r10, r10
        movq	r12, 18446744069414584321
        sbbq	r13, 0
        andq	r11, r13
        andq	r12, r13
        subq	rax, r13
        sbbq	r8, r11
        movq	[%rcx], rax
        sbbq	r9, 0
        movq	[%rcx+8], r8
        sbbq	r10, r12
        movq	[%rcx+16], r9
        movq	[%rcx+24], r10
        pop	r13
        pop	r12
        repz retq
sp_256_mont_dbl_4 ENDP
; /* Triple a Montgomery form number (r = a + a + a % m).
;  *
;  * r   Result of Tripling.
;  * a   Number to triple in Montogmery form.
;  * m   Modulus (prime).
;  */
sp_256_mont_tpl_4 PROC
        push	r12
        push	r13
        movq	rax, [%rdx]
        movq	r8, [%rdx+8]
        movq	r9, [%rdx+16]
        movq	r10, [%rdx+24]
        xorq	r13, r13
        addq	rax, rax
        adcq	r8, r8
        movq	r11, 4294967295
        adcq	r9, r9
        adcq	r10, r10
        movq	r12, 18446744069414584321
        sbbq	r13, 0
        andq	r11, r13
        andq	r12, r13
        subq	rax, r13
        sbbq	r8, r11
        sbbq	r9, 0
        sbbq	r10, r12
        xorq	r13, r13
        addq	rax, [%rdx]
        adcq	r8, [%rdx+8]
        movq	r11, 4294967295
        adcq	r9, [%rdx+16]
        adcq	r10, [%rdx+24]
        movq	r12, 18446744069414584321
        sbbq	r13, 0
        andq	r11, r13
        andq	r12, r13
        subq	rax, r13
        sbbq	r8, r11
        movq	[%rcx], rax
        sbbq	r9, 0
        movq	[%rcx+8], r8
        sbbq	r10, r12
        movq	[%rcx+16], r9
        movq	[%rcx+24], r10
        pop	r13
        pop	r12
        repz retq
sp_256_mont_tpl_4 ENDP
; /* Subtract two Montgomery form numbers (r = a - b % m).
;  *
;  * r   Result of subtration.
;  * a   Number to subtract from in Montogmery form.
;  * b   Number to subtract with in Montogmery form.
;  * m   Modulus (prime).
;  */
sp_256_mont_sub_4 PROC
        push	r12
        push	r13
        movq	rax, [%rdx]
        movq	r9, [%rdx+8]
        movq	r10, [%rdx+16]
        movq	r11, [%rdx+24]
        subq	rax, [%r8]
        sbbq	r9, [%r8+8]
        movq	r12, 4294967295
        sbbq	r10, [%r8+16]
        movq	r13, 18446744069414584321
        sbbq	r11, [%r8+24]
        movq	r8, 0
        sbbq	r8, 0
        andq	r12, r8
        andq	r13, r8
        addq	rax, r8
        adcq	r9, r12
        movq	[%rcx], rax
        adcq	r10, 0
        movq	[%rcx+8], r9
        adcq	r11, r13
        movq	[%rcx+16], r10
        movq	[%rcx+24], r11
        pop	r13
        pop	r12
        repz retq
sp_256_mont_sub_4 ENDP
; /* Divide the number by 2 mod the modulus (prime). (r = a / 2 % m)
;  *
;  * r  Result of division by 2.
;  * a  Number to divide.
;  * m  Modulus (prime).
;  */
sp_256_div2_4 PROC
        push	r12
        push	r13
        movq	rax, [%rdx]
        movq	r8, [%rdx+8]
        movq	r9, [%rdx+16]
        movq	r10, [%rdx+24]
        movq	r11, 4294967295
        movq	r12, 18446744069414584321
        movq	r13, rax
        andq	r13, 1
        negq	r13
        andq	r11, r13
        andq	r12, r13
        addq	rax, r13
        adcq	r8, r11
        adcq	r9, 0
        adcq	r10, r12
        movq	r13, 0
        adcq	r13, 0
        shrdq	rax, r8, 1
        shrdq	r8, r9, 1
        shrdq	r9, r10, 1
        shrdq	r10, r13, 1
        movq	[%rcx], rax
        movq	[%rcx+8], r8
        movq	[%rcx+16], r9
        movq	[%rcx+24], r10
        pop	r13
        pop	r12
        repz retq
sp_256_div2_4 ENDP
; /* Multiply two Montogmery form numbers mod the modulus (prime).
;  * (r = a * b mod m)
;  *
;  * r   Result of multiplication.
;  * a   First number to multiply in Montogmery form.
;  * b   Second number to multiply in Montogmery form.
;  * m   Modulus (prime).
;  * mp  Montogmery mulitplier.
;  */
sp_256_mont_mul_avx2_4 PROC
        movq	rbp, r8
        movq	rcx, rdx
        movq	r8, rcx
        push	rbx
        push	rbp
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        ;  A[0] * B[0]
        movq	rdx, [%rbp]
        mulxq	r11, r10, [%rcx]
        ;  A[2] * B[0]
        mulxq	r13, r12, [%rcx+16]
        ;  A[1] * B[0]
        mulxq	r9, rax, [%rcx+8]
        xorq	rsi, rsi
        adcxq	r11, rax
        ;  A[1] * B[3]
        movq	rdx, [%rbp+24]
        mulxq	r15, r14, [%rcx+8]
        adcxq	r12, r9
        ;  A[0] * B[1]
        movq	rdx, [%rbp+8]
        mulxq	r9, rax, [%rcx]
        adoxq	r11, rax
        ;  A[2] * B[1]
        mulxq	rdi, rax, [%rcx+16]
        adoxq	r12, r9
        adcxq	r13, rax
        ;  A[1] * B[2]
        movq	rdx, [%rbp+16]
        mulxq	r9, rax, [%rcx+8]
        adcxq	r14, rdi
        adoxq	r13, rax
        adcxq	r15, rsi
        adoxq	r14, r9
        ;  A[0] * B[2]
        mulxq	r9, rax, [%rcx]
        adoxq	r15, rsi
        xorq	rdi, rdi
        adcxq	r12, rax
        ;  A[1] * B[1]
        movq	rdx, [%rbp+8]
        mulxq	rax, rdx, [%rcx+8]
        adcxq	r13, r9
        adoxq	r12, rdx
        ;  A[3] * B[1]
        movq	rdx, [%rbp+8]
        adoxq	r13, rax
        mulxq	r9, rax, [%rcx+24]
        adcxq	r14, rax
        ;  A[2] * B[2]
        movq	rdx, [%rbp+16]
        mulxq	rax, rdx, [%rcx+16]
        adcxq	r15, r9
        adoxq	r14, rdx
        ;  A[3] * B[3]
        movq	rdx, [%rbp+24]
        adoxq	r15, rax
        mulxq	r9, rax, [%rcx+24]
        adoxq	rdi, rsi
        adcxq	rdi, rax
        ;  A[0] * B[3]
        mulxq	rax, rdx, [%rcx]
        adcxq	rsi, r9
        xorq	r9, r9
        adcxq	r13, rdx
        ;  A[3] * B[0]
        movq	rdx, [%rcx+24]
        adcxq	r14, rax
        mulxq	rax, rbx, [%rbp]
        adoxq	r13, rbx
        adoxq	r14, rax
        ;  A[3] * B[2]
        mulxq	rax, rdx, [%rbp+16]
        adcxq	r15, rdx
        ;  A[2] * B[3]
        movq	rdx, [%rbp+24]
        adcxq	rdi, rax
        mulxq	rdx, rax, [%rcx+16]
        adcxq	rsi, r9
        adoxq	r15, rax
        adoxq	rdi, rdx
        adoxq	rsi, r9
        ; Start Reduction
        ; mu = a[0]-a[3] + a[0]-a[2] << 32 << 64 + (a[0] * 2) << 192
        ;    - a[0] << 32 << 192
        ;   + (a[0] * 2) << 192
        movq	rax, r10
        movq	rdx, r13
        addq	rdx, r10
        movq	rcx, r11
        addq	rdx, r10
        movq	rbp, r12
        ;   a[0]-a[2] << 32
        shlq	r10, 32
        shldq	r12, rcx, 32
        shldq	r11, rax, 32
        ;   - a[0] << 32 << 192
        subq	rdx, r10
        ;   + a[0]-a[2] << 32 << 64
        addq	rcx, r10
        adcq	rbp, r11
        adcq	rdx, r12
        ; a += (mu << 256) - (mu << 224) + (mu << 192) + (mu << 96) - mu
        ;   a += mu << 256
        xorq	r10, r10
        addq	r14, rax
        adcq	r15, rcx
        adcq	rdi, rbp
        adcq	rsi, rdx
        sbbq	r10, 0
        ;   a += mu << 192
        addq	r13, rax
        adcq	r14, rcx
        adcq	r15, rbp
        adcq	rdi, rdx
        adcq	rsi, 0
        sbbq	r10, 0
        ; mu <<= 32
        movq	r9, rdx
        shldq	rdx, rbp, 32
        shldq	rbp, rcx, 32
        shldq	rcx, rax, 32
        shrq	r9, 32
        shlq	rax, 32
        ;   a += (mu << 32) << 64
        addq	r13, rbp
        adcq	r14, rdx
        adcq	r15, r9
        adcq	rdi, 0
        adcq	rsi, 0
        sbbq	r10, 0
        ;   a -= (mu << 32) << 192
        subq	r13, rax
        movq	rax, 4294967295
        sbbq	r14, rcx
        movq	rcx, 18446744069414584321
        sbbq	r15, rbp
        sbbq	rdi, rdx
        sbbq	rsi, r9
        adcq	r10, 0
        ; mask m and sub from result if overflow
        ;  m[0] = -1 & mask = mask
        andq	rax, r10
        ;  m[2] =  0 & mask = 0
        andq	rcx, r10
        subq	r14, r10
        sbbq	r15, rax
        sbbq	rdi, 0
        sbbq	rsi, rcx
        movq	[%r8], r14
        movq	[%r8+8], r15
        movq	[%r8+16], rdi
        movq	[%r8+24], rsi
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rbp
        pop	rbx
        repz retq
sp_256_mont_mul_avx2_4 ENDP
; /* Square the Montgomery form number mod the modulus (prime). (r = a * a mod m)
;  *
;  * r   Result of squaring.
;  * a   Number to square in Montogmery form.
;  * m   Modulus (prime).
;  * mp  Montogmery mulitplier.
;  */
sp_256_mont_sqr_avx2_4 PROC
        movq	rax, rdx
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        ; A[0] * A[1]
        movq	rdx, [%rax]
        mulxq	r12, r11, [%rax+8]
        ; A[0] * A[3]
        mulxq	r14, r13, [%rax+24]
        ; A[2] * A[1]
        movq	rdx, [%rax+16]
        mulxq	rbx, r9, [%rax+8]
        xorq	rsi, rsi
        adoxq	r13, r9
        ; A[2] * A[3]
        mulxq	rdi, r15, [%rax+24]
        adoxq	r14, rbx
        ; A[2] * A[0]
        mulxq	rbx, r9, [%rax]
        adoxq	r15, rsi
        adcxq	r12, r9
        adoxq	rdi, rsi
        ; A[1] * A[3]
        movq	rdx, [%rax+8]
        mulxq	r10, r8, [%rax+24]
        adcxq	r13, rbx
        adcxq	r14, r8
        adcxq	r15, r10
        adcxq	rdi, rsi
        ; Double with Carry Flag
        ; A[0] * A[0]
        movq	rdx, [%rax]
        mulxq	r8, r10, rdx
        adcxq	r11, r11
        adcxq	r12, r12
        adoxq	r11, r8
        ; A[1] * A[1]
        movq	rdx, [%rax+8]
        mulxq	rbx, r9, rdx
        adcxq	r13, r13
        adoxq	r12, r9
        ; A[2] * A[2]
        movq	rdx, [%rax+16]
        mulxq	r9, r8, rdx
        adcxq	r14, r14
        adoxq	r13, rbx
        adcxq	r15, r15
        adoxq	r14, r8
        adcxq	rdi, rdi
        ; A[3] * A[3]
        movq	rdx, [%rax+24]
        mulxq	rbx, r8, rdx
        adoxq	r15, r9
        adcxq	rsi, rsi
        adoxq	rdi, r8
        adoxq	rsi, rbx
        ; Start Reduction
        ; mu = a[0]-a[3] + a[0]-a[2] << 32 << 64 + (a[0] * 2) << 192
        ;    - a[0] << 32 << 192
        ;   + (a[0] * 2) << 192
        movq	rax, r10
        movq	rdx, r13
        addq	rdx, r10
        movq	rax, r11
        addq	rdx, r10
        movq	r9, r12
        ;   a[0]-a[2] << 32
        shlq	r10, 32
        shldq	r12, rax, 32
        shldq	r11, rax, 32
        ;   - a[0] << 32 << 192
        subq	rdx, r10
        ;   + a[0]-a[2] << 32 << 64
        addq	rax, r10
        adcq	r9, r11
        adcq	rdx, r12
        ; a += (mu << 256) - (mu << 224) + (mu << 192) + (mu << 96) - mu
        ;   a += mu << 256
        movq	r10, 0
        addq	r14, rax
        adcq	r15, rax
        adcq	rdi, r9
        adcq	rsi, rdx
        sbbq	r10, 0
        ;   a += mu << 192
        addq	r13, rax
        adcq	r14, rax
        adcq	r15, r9
        adcq	rdi, rdx
        adcq	rsi, 0
        sbbq	r10, 0
        ; mu <<= 32
        movq	rbx, rdx
        shldq	rdx, r9, 32
        shldq	r9, rax, 32
        shldq	rax, rax, 32
        shrq	rbx, 32
        shlq	rax, 32
        ;   a += (mu << 32) << 64
        addq	r13, r9
        adcq	r14, rdx
        adcq	r15, rbx
        adcq	rdi, 0
        adcq	rsi, 0
        sbbq	r10, 0
        ;   a -= (mu << 32) << 192
        subq	r13, rax
        movq	rax, 4294967295
        sbbq	r14, rax
        movq	rax, 18446744069414584321
        sbbq	r15, r9
        sbbq	rdi, rdx
        sbbq	rsi, rbx
        adcq	r10, 0
        ; mask m and sub from result if overflow
        ;  m[0] = -1 & mask = mask
        andq	rax, r10
        ;  m[2] =  0 & mask = 0
        andq	rax, r10
        subq	r14, r10
        sbbq	r15, rax
        sbbq	rdi, 0
        sbbq	rsi, rax
        movq	[%rcx], r14
        movq	[%rcx+8], r15
        movq	[%rcx+16], rdi
        movq	[%rcx+24], rsi
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        repz retq
sp_256_mont_sqr_avx2_4 ENDP
; /* Add 1 to a. (a = a + 1)
;  *
;  * a  A single precision integer.
;  */
sp_256_add_one_4 PROC
        addq	[%rcx], 1
        adcq	[%rcx+8], 0
        adcq	[%rcx+16], 0
        adcq	[%rcx+24], 0
        repz retq
sp_256_add_one_4 ENDP
; /* Add b to a into r. (r = a + b)
;  *
;  * r  A single precision integer.
;  * a  A single precision integer.
;  * b  A single precision integer.
;  */
sp_256_add_4 PROC
        xorq	rax, rax
        movq	r9, [%rdx]
        addq	r9, [%r8]
        movq	[%rcx], r9
        movq	r9, [%rdx+8]
        adcq	r9, [%r8+8]
        movq	[%rcx+8], r9
        movq	r9, [%rdx+16]
        adcq	r9, [%r8+16]
        movq	[%rcx+16], r9
        movq	r9, [%rdx+24]
        adcq	r9, [%r8+24]
        movq	[%rcx+24], r9
        adcq	rax, 0
        repz retq
sp_256_add_4 ENDP
; /* Multiply a and b into r. (r = a * b)
;  *
;  * r  A single precision integer.
;  * a  A single precision integer.
;  * b  A single precision integer.
;  */
sp_256_mul_4 PROC
        movq	rcx, rdx
        movq	r9, rcx
        push	r12
        subq	rsp, 32
        ; A[0] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx]
        xorq	r12, r12
        movq	[%rsp], rax
        movq	r11, rdx
        ; A[0] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx]
        xorq	r10, r10
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[1] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+8]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        movq	[%rsp+8], r11
        ; A[0] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx]
        xorq	r11, r11
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[1] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+8]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[2] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+16]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        movq	[%rsp+16], r12
        ; A[0] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx]
        xorq	r12, r12
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[1] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+8]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[2] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+16]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        ; A[3] * B[0]
        movq	rax, [%r8]
        mulq	[%rcx+24]
        addq	r10, rax
        adcq	r11, rdx
        adcq	r12, 0
        movq	[%rsp+24], r10
        ; A[1] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+8]
        xorq	r10, r10
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[2] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+16]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        ; A[3] * B[1]
        movq	rax, [%r8+8]
        mulq	[%rcx+24]
        addq	r11, rax
        adcq	r12, rdx
        adcq	r10, 0
        movq	[%r9+32], r11
        ; A[2] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+16]
        xorq	r11, r11
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[3] * B[2]
        movq	rax, [%r8+16]
        mulq	[%rcx+24]
        addq	r12, rax
        adcq	r10, rdx
        adcq	r11, 0
        movq	[%r9+40], r12
        ; A[3] * B[3]
        movq	rax, [%r8+24]
        mulq	[%rcx+24]
        addq	r10, rax
        adcq	r11, rdx
        movq	[%r9+48], r10
        movq	[%r9+56], r11
        movq	rax, [%rsp]
        movq	rdx, [%rsp+8]
        movq	r10, [%rsp+16]
        movq	r11, [%rsp+24]
        movq	[%r9], rax
        movq	[%r9+8], rdx
        movq	[%r9+16], r10
        movq	[%r9+24], r11
        addq	rsp, 32
        pop	r12
        repz retq
sp_256_mul_4 ENDP
; /* Multiply a and b into r. (r = a * b)
;  *
;  * r   Result of multiplication.
;  * a   First number to multiply.
;  * b   Second number to multiply.
;  */
sp_256_mul_avx2_4 PROC
        movq	rax, rdx
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        ; A[0] * B[0]
        movq	rdx, [%r8]
        mulxq	r12, r11, [%rax]
        ; A[2] * B[0]
        mulxq	r14, r13, [%rax+16]
        ; A[1] * B[0]
        mulxq	r10, r9, [%rax+8]
        xorq	rbx, rbx
        adcxq	r12, r9
        ; A[1] * B[3]
        movq	rdx, [%r8+24]
        mulxq	rdi, r15, [%rax+8]
        adcxq	r13, r10
        ; A[0] * B[1]
        movq	rdx, [%r8+8]
        mulxq	r10, r9, [%rax]
        adoxq	r12, r9
        ; A[2] * B[1]
        mulxq	rsi, r9, [%rax+16]
        adoxq	r13, r10
        adcxq	r14, r9
        ; A[1] * B[2]
        movq	rdx, [%r8+16]
        mulxq	r10, r9, [%rax+8]
        adcxq	r15, rsi
        adoxq	r14, r9
        adcxq	rdi, rbx
        adoxq	r15, r10
        ; A[0] * B[2]
        mulxq	r10, r9, [%rax]
        adoxq	rdi, rbx
        xorq	rsi, rsi
        adcxq	r13, r9
        ; A[1] * B[1]
        movq	rdx, [%r8+8]
        mulxq	r9, rdx, [%rax+8]
        adcxq	r14, r10
        adoxq	r13, rdx
        ; A[3] * B[1]
        movq	rdx, [%r8+8]
        adoxq	r14, r9
        mulxq	r10, r9, [%rax+24]
        adcxq	r15, r9
        ; A[2] * B[2]
        movq	rdx, [%r8+16]
        mulxq	r9, rdx, [%rax+16]
        adcxq	rdi, r10
        adoxq	r15, rdx
        ; A[3] * B[3]
        movq	rdx, [%r8+24]
        adoxq	rdi, r9
        mulxq	r10, r9, [%rax+24]
        adoxq	rsi, rbx
        adcxq	rsi, r9
        ; A[0] * B[3]
        mulxq	r9, rdx, [%rax]
        adcxq	rbx, r10
        xorq	r10, r10
        adcxq	r14, rdx
        ; A[3] * B[0]
        movq	rdx, [%r8]
        adcxq	r15, r9
        mulxq	r9, rdx, [%rax+24]
        adoxq	r14, rdx
        adoxq	r15, r9
        ; A[2] * B[3]
        movq	rdx, [%r8+24]
        mulxq	r9, rdx, [%rax+16]
        adcxq	rdi, rdx
        ; A[3] * B[2]
        movq	rdx, [%r8+16]
        adcxq	rsi, r9
        mulxq	rdx, r9, [%rax+24]
        adcxq	rbx, r10
        adoxq	rdi, r9
        adoxq	rsi, rdx
        adoxq	rbx, r10
        movq	[%rcx], r11
        movq	[%rcx+8], r12
        movq	[%rcx+16], r13
        movq	[%rcx+24], r14
        movq	[%rcx+32], r15
        movq	[%rcx+40], rdi
        movq	[%rcx+48], rsi
        movq	[%rcx+56], rbx
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        repz retq
sp_256_mul_avx2_4 ENDP
; /* Sub b from a into a. (a -= b)
;  *
;  * a  A single precision integer and result.
;  * b  A single precision integer.
;  */
sp_256_sub_in_place_4 PROC
        xorq	rax, rax
        movq	r8, [%rdx]
        movq	r9, [%rdx+8]
        movq	r10, [%rdx+16]
        movq	r11, [%rdx+24]
        subq	[%rcx], r8
        sbbq	[%rcx+8], r9
        sbbq	[%rcx+16], r10
        sbbq	[%rcx+24], r11
        sbbq	rax, 0
        repz retq
sp_256_sub_in_place_4 ENDP
; /* Mul a by digit b into r. (r = a * b)
;  *
;  * r  A single precision integer.
;  * a  A single precision integer.
;  * b  A single precision digit.
;  */
sp_256_mul_d_4 PROC
        movq	rcx, rdx
        movq	r9, rcx
        push	r12
        ; A[0] * B
        movq	rax, r8
        xorq	r12, r12
        mulq	[%rcx]
        movq	r10, rax
        movq	r11, rdx
        movq	[%r9], r10
        ; A[1] * B
        movq	rax, r8
        xorq	r10, r10
        mulq	[%rcx+8]
        addq	r11, rax
        movq	[%r9+8], r11
        adcq	r12, rdx
        adcq	r10, 0
        ; A[2] * B
        movq	rax, r8
        xorq	r11, r11
        mulq	[%rcx+16]
        addq	r12, rax
        movq	[%r9+16], r12
        adcq	r10, rdx
        adcq	r11, 0
        ; # A[3] * B
        movq	rax, r8
        mulq	[%rcx+24]
        addq	r10, rax
        adcq	r11, rdx
        movq	[%r9+24], r10
        movq	[%r9+32], r11
        pop	r12
        repz retq
sp_256_mul_d_4 ENDP
IFDEF HAVE_INTEL_AVX2
; /* Mul a by digit b into r. (r = a * b)
;  *
;  * r  A single precision integer.
;  * a  A single precision integer.
;  * b  A single precision digit.
;  */
sp_256_mul_d_avx2_4 PROC
        movq	rax, rdx
        push	r12
        push	r13
        ; A[0] * B
        movq	rdx, r8
        xorq	r13, r13
        mulxq	r12, r11, [%rax]
        movq	[%rcx], r11
        ; A[1] * B
        mulxq	r10, r9, [%rax+8]
        movq	r11, r13
        adcxq	r12, r9
        movq	[%rcx+8], r12
        adoxq	r11, r10
        ; A[2] * B
        mulxq	r10, r9, [%rax+16]
        movq	r12, r13
        adcxq	r11, r9
        movq	[%rcx+16], r11
        adoxq	r12, r10
        ; A[3] * B
        mulxq	r10, r9, [%rax+24]
        movq	r11, r13
        adcxq	r12, r9
        adoxq	r11, r10
        adcxq	r11, r13
        movq	[%rcx+24], r12
        movq	[%rcx+32], r11
        pop	r13
        pop	r12
        repz retq
sp_256_mul_d_avx2_4 ENDP
ENDIF
; /* Square a and put result in r. (r = a * a)
;  *
;  * r  A single precision integer.
;  * a  A single precision integer.
;  */
sp_256_sqr_4 PROC
        movq	rcx, rdx
        movq	r8, rcx
        push	r12
        push	r13
        push	r14
        subq	rsp, 32
        ; A[0] * A[0]
        movq	rax, [%rcx]
        mulq	rax
        xorq	r11, r11
        movq	[%rsp], rax
        movq	r10, rdx
        ; A[0] * A[1]
        movq	rax, [%rcx+8]
        mulq	[%rcx]
        xorq	r9, r9
        addq	r10, rax
        adcq	r11, rdx
        adcq	r9, 0
        addq	r10, rax
        adcq	r11, rdx
        adcq	r9, 0
        movq	[%rsp+8], r10
        ; A[0] * A[2]
        movq	rax, [%rcx+16]
        mulq	[%rcx]
        xorq	r10, r10
        addq	r11, rax
        adcq	r9, rdx
        adcq	r10, 0
        addq	r11, rax
        adcq	r9, rdx
        adcq	r10, 0
        ; A[1] * A[1]
        movq	rax, [%rcx+8]
        mulq	rax
        addq	r11, rax
        adcq	r9, rdx
        adcq	r10, 0
        movq	[%rsp+16], r11
        ; A[0] * A[3]
        movq	rax, [%rcx+24]
        mulq	[%rcx]
        xorq	r11, r11
        addq	r9, rax
        adcq	r10, rdx
        adcq	r11, 0
        addq	r9, rax
        adcq	r10, rdx
        adcq	r11, 0
        ; A[1] * A[2]
        movq	rax, [%rcx+16]
        mulq	[%rcx+8]
        addq	r9, rax
        adcq	r10, rdx
        adcq	r11, 0
        addq	r9, rax
        adcq	r10, rdx
        adcq	r11, 0
        movq	[%rsp+24], r9
        ; A[1] * A[3]
        movq	rax, [%rcx+24]
        mulq	[%rcx+8]
        xorq	r9, r9
        addq	r10, rax
        adcq	r11, rdx
        adcq	r9, 0
        addq	r10, rax
        adcq	r11, rdx
        adcq	r9, 0
        ; A[2] * A[2]
        movq	rax, [%rcx+16]
        mulq	rax
        addq	r10, rax
        adcq	r11, rdx
        adcq	r9, 0
        movq	[%r8+32], r10
        ; A[2] * A[3]
        movq	rax, [%rcx+24]
        mulq	[%rcx+16]
        xorq	r10, r10
        addq	r11, rax
        adcq	r9, rdx
        adcq	r10, 0
        addq	r11, rax
        adcq	r9, rdx
        adcq	r10, 0
        movq	[%r8+40], r11
        ; A[3] * A[3]
        movq	rax, [%rcx+24]
        mulq	rax
        addq	r9, rax
        adcq	r10, rdx
        movq	[%r8+48], r9
        movq	[%r8+56], r10
        movq	rax, [%rsp]
        movq	rdx, [%rsp+8]
        movq	r12, [%rsp+16]
        movq	r13, [%rsp+24]
        movq	[%r8], rax
        movq	[%r8+8], rdx
        movq	[%r8+16], r12
        movq	[%r8+24], r13
        addq	rsp, 32
        pop	r14
        pop	r13
        pop	r12
        repz retq
sp_256_sqr_4 ENDP
; /* Square a and put result in r. (r = a * a)
;  *
;  * r   Result of squaring.
;  * a   Number to square in Montogmery form.
;  */
sp_256_sqr_avx2_4 PROC
        movq	r8, rdx
        movq	r9, rcx
        push	rbx
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        ; A[0] * A[1]
        movq	rdx, [%r8]
        mulxq	r12, r11, [%r8+8]
        ; A[0] * A[3]
        mulxq	r14, r13, [%r8+24]
        ; A[2] * A[1]
        movq	rdx, [%r8+16]
        mulxq	rbx, rcx, [%r8+8]
        xorq	rsi, rsi
        adoxq	r13, rcx
        ; A[2] * A[3]
        mulxq	rdi, r15, [%r8+24]
        adoxq	r14, rbx
        ; A[2] * A[0]
        mulxq	rbx, rcx, [%r8]
        adoxq	r15, rsi
        adcxq	r12, rcx
        adoxq	rdi, rsi
        ; A[1] * A[3]
        movq	rdx, [%r8+8]
        mulxq	r10, rax, [%r8+24]
        adcxq	r13, rbx
        adcxq	r14, rax
        adcxq	r15, r10
        adcxq	rdi, rsi
        ; Double with Carry Flag
        xorq	rsi, rsi
        ; A[0] * A[0]
        movq	rdx, [%r8]
        mulxq	rax, r10, rdx
        adcxq	r11, r11
        ; A[1] * A[1]
        movq	rdx, [%r8+8]
        mulxq	rbx, rcx, rdx
        adcxq	r12, r12
        adoxq	r11, rax
        adcxq	r13, r13
        adoxq	r12, rcx
        ; A[2] * A[2]
        movq	rdx, [%r8+16]
        mulxq	rcx, rax, rdx
        adcxq	r14, r14
        adoxq	r13, rbx
        adcxq	r15, r15
        adoxq	r14, rax
        ; A[3] * A[3]
        movq	rdx, [%r8+24]
        mulxq	rbx, rax, rdx
        adcxq	rdi, rdi
        adoxq	r15, rcx
        adcxq	rsi, rsi
        adoxq	rdi, rax
        adoxq	rsi, rbx
        movq	[%r9], r10
        movq	[%r9+8], r11
        movq	[%r9+16], r12
        movq	[%r9+24], r13
        movq	[%r9+32], r14
        movq	[%r9+40], r15
        movq	[%r9+48], rdi
        movq	[%r9+56], rsi
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        pop	rbx
        repz retq
sp_256_sqr_avx2_4 ENDP
IFDEF HAVE_INTEL_AVX2
; /* Reduce the number back to 256 bits using Montgomery reduction.
;  *
;  * a   A single precision number to reduce in place.
;  * m   The single precision number representing the modulus.
;  * mp  The digit representing the negative inverse of m mod 2^n.
;  */
sp_256_mont_reduce_avx2_4 PROC
        movq	rax, r8
        movq	r10, rdx
        movq	r11, rcx
        push	r12
        push	r13
        push	r14
        push	r15
        push	rdi
        push	rsi
        push	rbx
        movq	r14, [%r11]
        movq	r15, [%r11+8]
        movq	rdi, [%r11+16]
        movq	rsi, [%r11+24]
        xorq	r13, r13
        xorq	r12, r12
        ; a[0-4] += m[0-3] * mu = m[0-3] * (a[0] * mp)
        movq	rbx, [%r11+32]
        ;   mu = a[0] * mp
        movq	rdx, r14
        mulxq	rcx, rdx, rax
        ;   a[0] += m[0] * mu
        mulx	r9, r8, [%r10]
        adcxq	r14, r8
        ;   a[1] += m[1] * mu
        mulx	rcx, r8, [%r10+8]
        adoxq	r15, r9
        adcxq	r15, r8
        ;   a[2] += m[2] * mu
        mulx	r9, r8, [%r10+16]
        adoxq	rdi, rcx
        adcxq	rdi, r8
        ;   a[3] += m[3] * mu
        mulx	rcx, r8, [%r10+24]
        adoxq	rsi, r9
        adcxq	rsi, r8
        ;   a[4] += carry
        adoxq	rbx, rcx
        adcxq	rbx, r12
        ;   carry
        adoxq	r13, r12
        adcxq	r13, r12
        ; a[1-5] += m[0-3] * mu = m[0-3] * (a[1] * mp)
        movq	r14, [%r11+40]
        ;   mu = a[1] * mp
        movq	rdx, r15
        mulxq	rcx, rdx, rax
        ;   a[1] += m[0] * mu
        mulx	r9, r8, [%r10]
        adcxq	r15, r8
        ;   a[2] += m[1] * mu
        mulx	rcx, r8, [%r10+8]
        adoxq	rdi, r9
        adcxq	rdi, r8
        ;   a[3] += m[2] * mu
        mulx	r9, r8, [%r10+16]
        adoxq	rsi, rcx
        adcxq	rsi, r8
        ;   a[4] += m[3] * mu
        mulx	rcx, r8, [%r10+24]
        adoxq	rbx, r9
        adcxq	rbx, r8
        ;   a[5] += carry
        adoxq	r14, rcx
        adcxq	r14, r13
        movq	r13, r12
        ;   carry
        adoxq	r13, r12
        adcxq	r13, r12
        ; a[2-6] += m[0-3] * mu = m[0-3] * (a[2] * mp)
        movq	r15, [%r11+48]
        ;   mu = a[2] * mp
        movq	rdx, rdi
        mulxq	rcx, rdx, rax
        ;   a[2] += m[0] * mu
        mulx	r9, r8, [%r10]
        adcxq	rdi, r8
        ;   a[3] += m[1] * mu
        mulx	rcx, r8, [%r10+8]
        adoxq	rsi, r9
        adcxq	rsi, r8
        ;   a[4] += m[2] * mu
        mulx	r9, r8, [%r10+16]
        adoxq	rbx, rcx
        adcxq	rbx, r8
        ;   a[5] += m[3] * mu
        mulx	rcx, r8, [%r10+24]
        adoxq	r14, r9
        adcxq	r14, r8
        ;   a[6] += carry
        adoxq	r15, rcx
        adcxq	r15, r13
        movq	r13, r12
        ;   carry
        adoxq	r13, r12
        adcxq	r13, r12
        ; a[3-7] += m[0-3] * mu = m[0-3] * (a[3] * mp)
        movq	rdi, [%r11+56]
        ;   mu = a[3] * mp
        movq	rdx, rsi
        mulxq	rcx, rdx, rax
        ;   a[3] += m[0] * mu
        mulx	r9, r8, [%r10]
        adcxq	rsi, r8
        ;   a[4] += m[1] * mu
        mulx	rcx, r8, [%r10+8]
        adoxq	rbx, r9
        adcxq	rbx, r8
        ;   a[5] += m[2] * mu
        mulx	r9, r8, [%r10+16]
        adoxq	r14, rcx
        adcxq	r14, r8
        ;   a[6] += m[3] * mu
        mulx	rcx, r8, [%r10+24]
        adoxq	r15, r9
        adcxq	r15, r8
        ;   a[7] += carry
        adoxq	rdi, rcx
        adcxq	rdi, r13
        movq	r13, r12
        ;   carry
        adoxq	r13, r12
        adcxq	r13, r12
        ; Subtract mod if carry
        negq	r13
        movq	r8, 17562291160714782033
        movq	r9, 13611842547513532036
        movq	rdx, 18446744069414584320
        andq	r8, r13
        andq	r9, r13
        movq	r13, r13
        andq	rdx, r13
        subq	rbx, r8
        sbbq	r14, r9
        sbbq	r15, r13
        sbbq	rdi, rdx
        movq	[%r11], rbx
        movq	[%r11+8], r14
        movq	[%r11+16], r15
        movq	[%r11+24], rdi
        pop	rbx
        pop	rsi
        pop	rdi
        pop	r15
        pop	r14
        pop	r13
        pop	r12
        repz retq
sp_256_mont_reduce_avx2_4 ENDP
ENDIF
_text ENDS
END
