; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -o - %s | FileCheck %s

target datalayout = "e-m:o-i64:64-i128:128-n32:64-S128"
target triple = "arm64-apple-ios"

; CHECK-LABEL: lCPI0_0:
; CHECK-NEXT:     .byte    0                               ; 0x0
; CHECK-NEXT:     .byte    4                               ; 0x4
; CHECK-NEXT:     .byte    8                               ; 0x8
; CHECK-NEXT:     .byte    12                              ; 0xc
; CHECK-NEXT:     .byte    16                              ; 0x10
; CHECK-NEXT:     .byte    20                              ; 0x14
; CHECK-NEXT:     .byte    24                              ; 0x18
; CHECK-NEXT:     .byte    28                              ; 0x1c
; CHECK-NEXT:     .byte    255                             ; 0xff
; CHECK-NEXT:     .byte    255                             ; 0xff
; CHECK-NEXT:     .byte    255                             ; 0xff
; CHECK-NEXT:     .byte    255                             ; 0xff
; CHECK-NEXT:     .byte    255                             ; 0xff
; CHECK-NEXT:     .byte    255                             ; 0xff
; CHECK-NEXT:     .byte    255                             ; 0xff
; CHECK-NEXT:     .byte    255                             ; 0xff

; It's profitable to convert the fptoui float -> i8 to first convert from
; float -> i32 and then use tbl for the truncate in a loop, so the mask can be
; materialized outside the loop.
define void @fptoui_v8f32_to_v8i8_in_loop(ptr %A, ptr %dst) {
; CHECK-LABEL: fptoui_v8f32_to_v8i8_in_loop:
; CHECK:       ; %bb.0: ; %entry
; CHECK-NEXT:  Lloh0:
; CHECK-NEXT:    adrp x8, lCPI0_0@PAGE
; CHECK-NEXT:  Lloh1:
; CHECK-NEXT:    ldr q0, [x8, lCPI0_0@PAGEOFF]
; CHECK-NEXT:    mov x8, xzr
; CHECK-NEXT:  LBB0_1: ; %loop
; CHECK-NEXT:    ; =>This Inner Loop Header: Depth=1
; CHECK-NEXT:    add x9, x0, x8, lsl #5
; CHECK-NEXT:    add x8, x8, #1
; CHECK-NEXT:    cmp x8, #1000
; CHECK-NEXT:    ldp q2, q1, [x9]
; CHECK-NEXT:    fcvtzu.4s v4, v1
; CHECK-NEXT:    fcvtzu.4s v3, v2
; CHECK-NEXT:    tbl.16b v1, { v3, v4 }, v0
; CHECK-NEXT:    str d1, [x1], #16
; CHECK-NEXT:    b.eq LBB0_1
; CHECK-NEXT:  ; %bb.2: ; %exit
; CHECK-NEXT:    ret
; CHECK-NEXT:    .loh AdrpLdr Lloh0, Lloh1
entry:
  br label %loop

loop:
  %iv = phi i64 [ 0, %entry ], [ %iv.next, %loop ]
  %gep.A = getelementptr inbounds <8 x float>, ptr %A, i64 %iv
  %l.A = load <8 x float>, ptr %gep.A
  %c = fptoui <8 x float> %l.A to <8 x i8>
  %gep.dst = getelementptr inbounds <16 x i8>, ptr %dst, i64 %iv
  store <8 x i8> %c, ptr %gep.dst
  %iv.next = add i64 %iv, 1
  %ec = icmp eq i64 %iv.next, 1000
  br i1 %ec, label %loop, label %exit

exit:
  ret void
}

; Not profitable to use tbl, as materializing the masks requires more
; instructions.
define void @fptoui_v8f32_to_v8i8_no_loop(ptr %A, ptr %dst) {
; CHECK-LABEL: fptoui_v8f32_to_v8i8_no_loop:
; CHECK:       ; %bb.0: ; %entry
; CHECK-NEXT:    ldp q0, q1, [x0]
; CHECK-NEXT:    fcvtzs.4s v1, v1
; CHECK-NEXT:    fcvtzs.4s v0, v0
; CHECK-NEXT:    uzp1.8h v0, v0, v1
; CHECK-NEXT:    xtn.8b v0, v0
; CHECK-NEXT:    str d0, [x1]
; CHECK-NEXT:    ret
entry:
  %l.A = load <8 x float>, ptr %A
  %c = fptoui <8 x float> %l.A to <8 x i8>
  store <8 x i8> %c, ptr %dst
  ret void
}

; CHECK-LABEL: lCPI2_0:
; CHECK-NEXT:    .byte    0                               ; 0x0
; CHECK-NEXT:    .byte    4                               ; 0x4
; CHECK-NEXT:    .byte    8                               ; 0x8
; CHECK-NEXT:    .byte    12                              ; 0xc
; CHECK-NEXT:    .byte    16                              ; 0x10
; CHECK-NEXT:    .byte    20                              ; 0x14
; CHECK-NEXT:    .byte    24                              ; 0x18
; CHECK-NEXT:    .byte    28                              ; 0x1c
; CHECK-NEXT:    .byte    32                              ; 0x20
; CHECK-NEXT:    .byte    36                              ; 0x24
; CHECK-NEXT:    .byte    40                              ; 0x28
; CHECK-NEXT:    .byte    44                              ; 0x2c
; CHECK-NEXT:    .byte    48                              ; 0x30
; CHECK-NEXT:    .byte    52                              ; 0x34
; CHECK-NEXT:    .byte    56                              ; 0x38
; CHECK-NEXT:    .byte    60                              ; 0x3c

; Tbl can also be used when combining multiple fptoui using a shuffle. The loop
; vectorizer may create such patterns.
define void @fptoui_2x_v8f32_to_v8i8_in_loop(ptr %A, ptr %B, ptr %dst) {
; CHECK-LABEL: fptoui_2x_v8f32_to_v8i8_in_loop:
; CHECK:       ; %bb.0: ; %entry
; CHECK-NEXT:  Lloh2:
; CHECK-NEXT:    adrp x8, lCPI2_0@PAGE
; CHECK-NEXT:  Lloh3:
; CHECK-NEXT:    ldr q0, [x8, lCPI2_0@PAGEOFF]
; CHECK-NEXT:    mov x8, xzr
; CHECK-NEXT:  LBB2_1: ; %loop
; CHECK-NEXT:    ; =>This Inner Loop Header: Depth=1
; CHECK-NEXT:    lsl x9, x8, #5
; CHECK-NEXT:    add x10, x0, x9
; CHECK-NEXT:    add x9, x1, x9
; CHECK-NEXT:    ldp q2, q1, [x10]
; CHECK-NEXT:    fcvtzu.4s v4, v1
; CHECK-NEXT:    ldp q7, q1, [x9]
; CHECK-NEXT:    fcvtzu.4s v3, v2
; CHECK-NEXT:    fcvtzu.4s v6, v1
; CHECK-NEXT:    fcvtzu.4s v5, v7
; CHECK-NEXT:    tbl.16b v1, { v3, v4, v5, v6 }, v0
; CHECK-NEXT:    str q1, [x2, x8, lsl #4]
; CHECK-NEXT:    add x8, x8, #1
; CHECK-NEXT:    cmp x8, #1000
; CHECK-NEXT:    b.eq LBB2_1
; CHECK-NEXT:  ; %bb.2: ; %exit
; CHECK-NEXT:    ret
; CHECK-NEXT:    .loh AdrpLdr Lloh2, Lloh3
entry:
  br label %loop

loop:
  %iv = phi i64 [ 0, %entry ], [ %iv.next, %loop ]
  %gep.A = getelementptr inbounds <8 x float>, ptr %A, i64 %iv
  %gep.B = getelementptr inbounds <8x float>, ptr %B, i64 %iv
  %l.A = load <8 x float>, ptr %gep.A
  %l.B = load <8 x float>, ptr %gep.B
  %c1 = fptoui <8 x float> %l.A to <8 x i8>
  %c2 = fptoui <8 x float> %l.B to <8 x i8>
  %s = shufflevector <8 x i8> %c1, <8 x i8> %c2, <16 x i32> <i32 0, i32 1, i32 2, i32 3, i32 4, i32 5, i32 6, i32 7, i32 8, i32 9, i32 10, i32 11, i32 12, i32 13, i32 14, i32 15>
  %gep.dst = getelementptr inbounds <16 x i8>, ptr %dst, i64 %iv
  store <16 x i8> %s, ptr %gep.dst
  %iv.next = add i64 %iv, 1
  %ec = icmp eq i64 %iv.next, 1000
  br i1 %ec, label %loop, label %exit

exit:
  ret void
}

; CHECK-LABEL: lCPI3_0:
; CHECK-NEXT:	.byte	0                               ; 0x0
; CHECK-NEXT:	.byte	36                              ; 0x24
; CHECK-NEXT:	.byte	8                               ; 0x8
; CHECK-NEXT:	.byte	12                              ; 0xc
; CHECK-NEXT:	.byte	16                              ; 0x10
; CHECK-NEXT:	.byte	20                              ; 0x14
; CHECK-NEXT:	.byte	24                              ; 0x18
; CHECK-NEXT:	.byte	44                              ; 0x2c
; CHECK-NEXT:	.byte	32                              ; 0x20
; CHECK-NEXT:	.byte	36                              ; 0x24
; CHECK-NEXT:	.byte	40                              ; 0x28
; CHECK-NEXT:	.byte	44                              ; 0x2c
; CHECK-NEXT:	.byte	48                              ; 0x30
; CHECK-NEXT:	.byte	12                              ; 0xc
; CHECK-NEXT:	.byte	56                              ; 0x38
; CHECK-NEXT:	.byte	60                              ; 0x3c

define void @fptoui_2x_v8f32_to_v8i8_in_loop_no_concat_shuffle(ptr %A, ptr %B, ptr %dst) {
; CHECK-LABEL: fptoui_2x_v8f32_to_v8i8_in_loop_no_concat_shuffle:
; CHECK:       ; %bb.0: ; %entry
; CHECK-NEXT:  Lloh4:
; CHECK-NEXT:    adrp x8, lCPI3_0@PAGE
; CHECK-NEXT:  Lloh5:
; CHECK-NEXT:    ldr q0, [x8, lCPI3_0@PAGEOFF]
; CHECK-NEXT:    mov x8, xzr
; CHECK-NEXT:  LBB3_1: ; %loop
; CHECK-NEXT:    ; =>This Inner Loop Header: Depth=1
; CHECK-NEXT:    lsl x9, x8, #5
; CHECK-NEXT:    add x10, x0, x9
; CHECK-NEXT:    add x9, x1, x9
; CHECK-NEXT:    ldp q2, q1, [x10]
; CHECK-NEXT:    fcvtzu.4s v4, v1
; CHECK-NEXT:    ldp q7, q1, [x9]
; CHECK-NEXT:    fcvtzu.4s v3, v2
; CHECK-NEXT:    fcvtzu.4s v6, v1
; CHECK-NEXT:    fcvtzu.4s v5, v7
; CHECK-NEXT:    tbl.16b v1, { v3, v4, v5, v6 }, v0
; CHECK-NEXT:    str q1, [x2, x8, lsl #4]
; CHECK-NEXT:    add x8, x8, #1
; CHECK-NEXT:    cmp x8, #1000
; CHECK-NEXT:    b.eq LBB3_1
; CHECK-NEXT:  ; %bb.2: ; %exit
; CHECK-NEXT:    ret
; CHECK-NEXT:    .loh AdrpLdr Lloh4, Lloh5
entry:
  br label %loop

loop:
  %iv = phi i64 [ 0, %entry ], [ %iv.next, %loop ]
  %gep.A = getelementptr inbounds <8 x float>, ptr %A, i64 %iv
  %gep.B = getelementptr inbounds <8x float>, ptr %B, i64 %iv
  %l.A = load <8 x float>, ptr %gep.A
  %l.B = load <8 x float>, ptr %gep.B
  %c1 = fptoui <8 x float> %l.A to <8 x i8>
  %c2 = fptoui <8 x float> %l.B to <8 x i8>
  %s = shufflevector <8 x i8> %c1, <8 x i8> %c2, <16 x i32> <i32 0, i32 9, i32 2, i32 3, i32 4, i32 5, i32 6, i32 11, i32 8, i32 9, i32 10, i32 11, i32 12, i32 3, i32 14, i32 15>
  %gep.dst = getelementptr inbounds <16 x i8>, ptr %dst, i64 %iv
  store <16 x i8> %s, ptr %gep.dst
  %iv.next = add i64 %iv, 1
  %ec = icmp eq i64 %iv.next, 1000
  br i1 %ec, label %loop, label %exit

exit:
  ret void
}

; CHECK-LABEL: lCPI4_0:
; CHECK-NEXT: 	.byte	0                               ; 0x0
; CHECK-NEXT: 	.byte	4                               ; 0x4
; CHECK-NEXT: 	.byte	8                               ; 0x8
; CHECK-NEXT: 	.byte	12                              ; 0xc
; CHECK-NEXT: 	.byte	16                              ; 0x10
; CHECK-NEXT: 	.byte	20                              ; 0x14
; CHECK-NEXT: 	.byte	24                              ; 0x18
; CHECK-NEXT: 	.byte	28                              ; 0x1c
; CHECK-NEXT: 	.byte	32                              ; 0x20
; CHECK-NEXT: 	.byte	36                              ; 0x24
; CHECK-NEXT: 	.byte	40                              ; 0x28
; CHECK-NEXT: 	.byte	44                              ; 0x2c
; CHECK-NEXT: 	.byte	48                              ; 0x30
; CHECK-NEXT: 	.byte	52                              ; 0x34
; CHECK-NEXT: 	.byte	56                              ; 0x38
; CHECK-NEXT: 	.byte	60                              ; 0x3c

define void @fptoui_v16f32_to_v16i8_in_loop(ptr %A, ptr %dst) {
; CHECK-LABEL: fptoui_v16f32_to_v16i8_in_loop:
; CHECK:       ; %bb.0: ; %entry
; CHECK-NEXT:  Lloh6:
; CHECK-NEXT:    adrp x8, lCPI4_0@PAGE
; CHECK-NEXT:  Lloh7:
; CHECK-NEXT:    ldr q0, [x8, lCPI4_0@PAGEOFF]
; CHECK-NEXT:    mov x8, xzr
; CHECK-NEXT:  LBB4_1: ; %loop
; CHECK-NEXT:    ; =>This Inner Loop Header: Depth=1
; CHECK-NEXT:    add x9, x0, x8, lsl #6
; CHECK-NEXT:    add x8, x8, #1
; CHECK-NEXT:    cmp x8, #1000
; CHECK-NEXT:    ldp q2, q1, [x9, #32]
; CHECK-NEXT:    fcvtzu.4s v6, v1
; CHECK-NEXT:    ldp q7, q1, [x9]
; CHECK-NEXT:    fcvtzu.4s v5, v2
; CHECK-NEXT:    fcvtzu.4s v4, v1
; CHECK-NEXT:    fcvtzu.4s v3, v7
; CHECK-NEXT:    tbl.16b v1, { v3, v4, v5, v6 }, v0
; CHECK-NEXT:    str q1, [x1], #32
; CHECK-NEXT:    b.eq LBB4_1
; CHECK-NEXT:  ; %bb.2: ; %exit
; CHECK-NEXT:    ret
; CHECK-NEXT:    .loh AdrpLdr Lloh6, Lloh7
entry:
  br label %loop

loop:
  %iv = phi i64 [ 0, %entry ], [ %iv.next, %loop ]
  %gep.A = getelementptr inbounds <16 x float>, ptr %A, i64 %iv
  %l.A = load <16 x float>, ptr %gep.A
  %c = fptoui <16 x float> %l.A to <16 x i8>
  %gep.dst = getelementptr inbounds <32 x i8>, ptr %dst, i64 %iv
  store <16 x i8> %c, ptr %gep.dst
  %iv.next = add i64 %iv, 1
  %ec = icmp eq i64 %iv.next, 1000
  br i1 %ec, label %loop, label %exit

exit:
  ret void
}

; CHECK-LABEL: lCPI5_0:
; CHECK-NEXT: 	.byte	0                               ; 0x0
; CHECK-NEXT: 	.byte	4                               ; 0x4
; CHECK-NEXT: 	.byte	8                               ; 0x8
; CHECK-NEXT: 	.byte	12                              ; 0xc
; CHECK-NEXT: 	.byte	16                              ; 0x10
; CHECK-NEXT: 	.byte	20                              ; 0x14
; CHECK-NEXT: 	.byte	24                              ; 0x18
; CHECK-NEXT: 	.byte	28                              ; 0x1c
; CHECK-NEXT: 	.byte	32                              ; 0x20
; CHECK-NEXT: 	.byte	36                              ; 0x24
; CHECK-NEXT: 	.byte	40                              ; 0x28
; CHECK-NEXT: 	.byte	44                              ; 0x2c
; CHECK-NEXT: 	.byte	48                              ; 0x30
; CHECK-NEXT: 	.byte	52                              ; 0x34
; CHECK-NEXT: 	.byte	56                              ; 0x38
; CHECK-NEXT: 	.byte	60                              ; 0x3c

define void @fptoui_2x_v16f32_to_v16i8_in_loop(ptr %A, ptr %B, ptr %dst) {
; CHECK-LABEL: fptoui_2x_v16f32_to_v16i8_in_loop:
; CHECK:       ; %bb.0: ; %entry
; CHECK-NEXT:  Lloh8:
; CHECK-NEXT:    adrp x8, lCPI5_0@PAGE
; CHECK-NEXT:  Lloh9:
; CHECK-NEXT:    ldr q0, [x8, lCPI5_0@PAGEOFF]
; CHECK-NEXT:    mov x8, xzr
; CHECK-NEXT:  LBB5_1: ; %loop
; CHECK-NEXT:    ; =>This Inner Loop Header: Depth=1
; CHECK-NEXT:    lsl x9, x8, #6
; CHECK-NEXT:    add x10, x1, x9
; CHECK-NEXT:    add x9, x0, x9
; CHECK-NEXT:    ldp q2, q1, [x10, #32]
; CHECK-NEXT:    ldp q3, q4, [x9, #32]
; CHECK-NEXT:    ldp q5, q6, [x10]
; CHECK-NEXT:    fcvtzu.4s v19, v1
; CHECK-NEXT:    fcvtzu.4s v18, v2
; CHECK-NEXT:    ldp q2, q1, [x9]
; CHECK-NEXT:    fcvtzu.4s v23, v4
; CHECK-NEXT:    fcvtzu.4s v17, v6
; CHECK-NEXT:    add x9, x2, x8, lsl #5
; CHECK-NEXT:    fcvtzu.4s v22, v3
; CHECK-NEXT:    fcvtzu.4s v16, v5
; CHECK-NEXT:    add x8, x8, #1
; CHECK-NEXT:    fcvtzu.4s v21, v1
; CHECK-NEXT:    cmp x8, #1000
; CHECK-NEXT:    fcvtzu.4s v20, v2
; CHECK-NEXT:    tbl.16b v1, { v16, v17, v18, v19 }, v0
; CHECK-NEXT:    tbl.16b v2, { v20, v21, v22, v23 }, v0
; CHECK-NEXT:    stp q2, q1, [x9]
; CHECK-NEXT:    b.eq LBB5_1
; CHECK-NEXT:  ; %bb.2: ; %exit
; CHECK-NEXT:    ret
; CHECK-NEXT:    .loh AdrpLdr Lloh8, Lloh9
entry:
  br label %loop

loop:
  %iv = phi i64 [ 0, %entry ], [ %iv.next, %loop ]
  %gep.A = getelementptr inbounds <16 x float>, ptr %A, i64 %iv
  %gep.B = getelementptr inbounds <16 x float>, ptr %B, i64 %iv
  %l.A = load <16 x float>, ptr %gep.A
  %l.B = load <16 x float>, ptr %gep.B
  %c1 = fptoui <16 x float> %l.A to <16 x i8>
  %c2 = fptoui <16 x float> %l.B to <16 x i8>
  %s = shufflevector <16 x i8> %c1, <16 x i8> %c2, <32 x i32> <i32 0, i32 1, i32 2, i32 3, i32 4, i32 5, i32 6, i32 7, i32 8, i32 9, i32 10, i32 11, i32 12, i32 13, i32 14, i32 15, i32 16, i32 17, i32 18, i32 19, i32 20, i32 21, i32 22, i32 23, i32 24, i32 25, i32 26, i32 27, i32 28, i32 29, i32 30, i32 31>
  %gep.dst = getelementptr inbounds <32 x i8>, ptr %dst, i64 %iv
  store <32 x i8> %s, ptr %gep.dst
  %iv.next = add i64 %iv, 1
  %ec = icmp eq i64 %iv.next, 1000
  br i1 %ec, label %loop, label %exit

exit:
  ret void
}

define void @fptoui_v8f32_to_v8i16_in_loop(ptr %A, ptr %dst) {
; CHECK-LABEL: fptoui_v8f32_to_v8i16_in_loop:
; CHECK:       ; %bb.0: ; %entry
; CHECK-NEXT:    mov x8, xzr
; CHECK-NEXT:  LBB6_1: ; %loop
; CHECK-NEXT:    ; =>This Inner Loop Header: Depth=1
; CHECK-NEXT:    add x9, x0, x8, lsl #5
; CHECK-NEXT:    ldp q0, q1, [x9]
; CHECK-NEXT:    fcvtzu.4s v1, v1
; CHECK-NEXT:    fcvtzu.4s v0, v0
; CHECK-NEXT:    uzp1.8h v0, v0, v1
; CHECK-NEXT:    str q0, [x1, x8, lsl #4]
; CHECK-NEXT:    add x8, x8, #1
; CHECK-NEXT:    cmp x8, #1000
; CHECK-NEXT:    b.eq LBB6_1
; CHECK-NEXT:  ; %bb.2: ; %exit
; CHECK-NEXT:    ret
entry:
  br label %loop

loop:
  %iv = phi i64 [ 0, %entry ], [ %iv.next, %loop ]
  %gep.A = getelementptr inbounds <8 x float>, ptr %A, i64 %iv
  %l.A = load <8 x float>, ptr %gep.A
  %c = fptoui <8 x float> %l.A to <8 x i16>
  %gep.dst = getelementptr inbounds <8 x i16>, ptr %dst, i64 %iv
  store <8 x i16> %c, ptr %gep.dst
  %iv.next = add i64 %iv, 1
  %ec = icmp eq i64 %iv.next, 1000
  br i1 %ec, label %loop, label %exit

exit:
  ret void
}

define void @fptoui_2x_v8f32_to_v8i16_in_loop(ptr %A, ptr %B, ptr %dst) {
; CHECK-LABEL: fptoui_2x_v8f32_to_v8i16_in_loop:
; CHECK:       ; %bb.0: ; %entry
; CHECK-NEXT:    mov x8, xzr
; CHECK-NEXT:  LBB7_1: ; %loop
; CHECK-NEXT:    ; =>This Inner Loop Header: Depth=1
; CHECK-NEXT:    lsl x9, x8, #5
; CHECK-NEXT:    add x8, x8, #1
; CHECK-NEXT:    cmp x8, #1000
; CHECK-NEXT:    add x10, x0, x9
; CHECK-NEXT:    add x11, x1, x9
; CHECK-NEXT:    add x9, x2, x9
; CHECK-NEXT:    ldp q0, q1, [x10]
; CHECK-NEXT:    ldp q2, q3, [x11]
; CHECK-NEXT:    fcvtzu.4s v1, v1
; CHECK-NEXT:    fcvtzu.4s v0, v0
; CHECK-NEXT:    fcvtzu.4s v3, v3
; CHECK-NEXT:    fcvtzu.4s v2, v2
; CHECK-NEXT:    uzp1.8h v0, v0, v1
; CHECK-NEXT:    uzp1.8h v1, v2, v3
; CHECK-NEXT:    stp q0, q1, [x9]
; CHECK-NEXT:    b.eq LBB7_1
; CHECK-NEXT:  ; %bb.2: ; %exit
; CHECK-NEXT:    ret
entry:
  br label %loop

loop:
  %iv = phi i64 [ 0, %entry ], [ %iv.next, %loop ]
  %gep.A = getelementptr inbounds <8 x float>, ptr %A, i64 %iv
  %gep.B = getelementptr inbounds <8 x float>, ptr %B, i64 %iv
  %l.A = load <8 x float>, ptr %gep.A
  %l.B = load <8 x float>, ptr %gep.B
  %c1 = fptoui <8 x float> %l.A to <8 x i16>
  %c2 = fptoui <8 x float> %l.B to <8 x i16>
  %s = shufflevector <8 x i16> %c1, <8 x i16> %c2, <16 x i32> <i32 0, i32 1, i32 2, i32 3, i32 4, i32 5, i32 6, i32 7, i32 8, i32 9, i32 10, i32 11, i32 12, i32 13, i32 14, i32 15>
  %gep.dst = getelementptr inbounds <16 x i16>, ptr %dst, i64 %iv
  store <16 x i16> %s, ptr %gep.dst
  %iv.next = add i64 %iv, 1
  %ec = icmp eq i64 %iv.next, 1000
  br i1 %ec, label %loop, label %exit

exit:
  ret void
}

; CHECK-LABEL: lCPI8_0:
; CHECK-NEXT:   .byte   4                               ; 0x4
; CHECK-NEXT:   .byte   255                             ; 0xff
; CHECK-NEXT:   .byte   255                             ; 0xff
; CHECK-NEXT:   .byte   255                             ; 0xff
; CHECK-NEXT:   .byte   5                               ; 0x5
; CHECK-NEXT:   .byte   255                             ; 0xff
; CHECK-NEXT:   .byte   255                             ; 0xff
; CHECK-NEXT:   .byte   255                             ; 0xff
; CHECK-NEXT:   .byte   6                               ; 0x6
; CHECK-NEXT:   .byte   255                             ; 0xff
; CHECK-NEXT:   .byte   255                             ; 0xff
; CHECK-NEXT:   .byte   255                             ; 0xff
; CHECK-NEXT:   .byte   7                               ; 0x7
; CHECK-NEXT:   .byte   255                             ; 0xff
; CHECK-NEXT:   .byte   255                             ; 0xff
; CHECK-NEXT:   .byte   255                             ; 0xff
; CHECK-NEXT: lCPI8_1:
; CHECK-NEXT:   .byte   0                               ; 0x0
; CHECK-NEXT:   .byte   255                             ; 0xff
; CHECK-NEXT:   .byte   255                             ; 0xff
; CHECK-NEXT:   .byte   255                             ; 0xff
; CHECK-NEXT:   .byte   1                               ; 0x1
; CHECK-NEXT:   .byte   255                             ; 0xff
; CHECK-NEXT:   .byte   255                             ; 0xff
; CHECK-NEXT:   .byte   255                             ; 0xff
; CHECK-NEXT:   .byte   2                               ; 0x2
; CHECK-NEXT:   .byte   255                             ; 0xff
; CHECK-NEXT:   .byte   255                             ; 0xff
; CHECK-NEXT:   .byte   255                             ; 0xff
; CHECK-NEXT:   .byte   3                               ; 0x3
; CHECK-NEXT:   .byte   255                             ; 0xff
; CHECK-NEXT:   .byte   255                             ; 0xff
; CHECK-NEXT:   .byte   255                             ; 0xff

define void @uitofp_v8i8_to_v8f32(ptr %src, ptr %dst) {
; CHECK-LABEL: uitofp_v8i8_to_v8f32:
; CHECK:       ; %bb.0: ; %entry
; CHECK-NEXT:  Lloh10:
; CHECK-NEXT:    adrp x8, lCPI8_0@PAGE
; CHECK-NEXT:  Lloh11:
; CHECK-NEXT:    adrp x9, lCPI8_1@PAGE
; CHECK-NEXT:  Lloh12:
; CHECK-NEXT:    ldr q0, [x8, lCPI8_0@PAGEOFF]
; CHECK-NEXT:  Lloh13:
; CHECK-NEXT:    ldr q1, [x9, lCPI8_1@PAGEOFF]
; CHECK-NEXT:    mov x8, xzr
; CHECK-NEXT:  LBB8_1: ; %loop
; CHECK-NEXT:    ; =>This Inner Loop Header: Depth=1
; CHECK-NEXT:    ldr d2, [x0, x8, lsl #3]
; CHECK-NEXT:    add x9, x1, x8, lsl #5
; CHECK-NEXT:    add x8, x8, #1
; CHECK-NEXT:    cmp x8, #1000
; CHECK-NEXT:    tbl.16b v3, { v2 }, v0
; CHECK-NEXT:    tbl.16b v2, { v2 }, v1
; CHECK-NEXT:    ucvtf.4s v3, v3
; CHECK-NEXT:    ucvtf.4s v2, v2
; CHECK-NEXT:    stp q2, q3, [x9]
; CHECK-NEXT:    b.eq LBB8_1
; CHECK-NEXT:  ; %bb.2: ; %exit
; CHECK-NEXT:    ret
; CHECK-NEXT:    .loh AdrpLdr Lloh11, Lloh13
; CHECK-NEXT:    .loh AdrpLdr Lloh10, Lloh12
entry:
  br label %loop

loop:
  %iv = phi i64 [ 0, %entry ], [ %iv.next, %loop ]
  %gep.src = getelementptr inbounds <8 x i8>, ptr %src, i64 %iv
  %l = load <8 x i8>, ptr %gep.src
  %conv = uitofp <8 x i8> %l to <8 x float>
  %gep.dst = getelementptr inbounds <8 x float>, ptr %dst, i64 %iv
  store <8 x float> %conv, ptr %gep.dst
  %iv.next = add i64 %iv, 1
  %ec = icmp eq i64 %iv.next, 1000
  br i1 %ec, label %loop, label %exit

exit:
  ret void
}

; CHECK-LABEL: lCPI9_0:
; CHECK-NEXT:     .byte   12                              ; 0xc
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   13                              ; 0xd
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   14                              ; 0xe
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   15                              ; 0xf
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT: lCPI9_1:
; CHECK-NEXT:     .byte   8                               ; 0x8
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   9                               ; 0x9
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   10                              ; 0xa
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   11                              ; 0xb
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT: lCPI9_2:
; CHECK-NEXT:     .byte   4                               ; 0x4
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   5                               ; 0x5
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   6                               ; 0x6
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   7                               ; 0x7
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT: lCPI9_3:
; CHECK-NEXT:     .byte   0                               ; 0x0
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   1                               ; 0x1
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   2                               ; 0x2
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   3                               ; 0x3
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   255                             ; 0xff
; CHECK-NEXT:     .byte   255                             ; 0xff

define void @uitofp_v16i8_to_v16f32(ptr %src, ptr %dst) {
; CHECK-LABEL: uitofp_v16i8_to_v16f32:
; CHECK:       ; %bb.0: ; %entry
; CHECK-NEXT:  Lloh14:
; CHECK-NEXT:    adrp x8, lCPI9_0@PAGE
; CHECK-NEXT:  Lloh15:
; CHECK-NEXT:    adrp x9, lCPI9_1@PAGE
; CHECK-NEXT:  Lloh16:
; CHECK-NEXT:    adrp x10, lCPI9_2@PAGE
; CHECK-NEXT:  Lloh17:
; CHECK-NEXT:    ldr q0, [x8, lCPI9_0@PAGEOFF]
; CHECK-NEXT:  Lloh18:
; CHECK-NEXT:    adrp x8, lCPI9_3@PAGE
; CHECK-NEXT:  Lloh19:
; CHECK-NEXT:    ldr q1, [x9, lCPI9_1@PAGEOFF]
; CHECK-NEXT:  Lloh20:
; CHECK-NEXT:    ldr q2, [x10, lCPI9_2@PAGEOFF]
; CHECK-NEXT:  Lloh21:
; CHECK-NEXT:    ldr q3, [x8, lCPI9_3@PAGEOFF]
; CHECK-NEXT:    mov x8, xzr
; CHECK-NEXT:  LBB9_1: ; %loop
; CHECK-NEXT:    ; =>This Inner Loop Header: Depth=1
; CHECK-NEXT:    ldr q4, [x0, x8, lsl #4]
; CHECK-NEXT:    add x9, x1, x8, lsl #6
; CHECK-NEXT:    add x8, x8, #1
; CHECK-NEXT:    cmp x8, #1000
; CHECK-NEXT:    tbl.16b v5, { v4 }, v0
; CHECK-NEXT:    tbl.16b v6, { v4 }, v1
; CHECK-NEXT:    tbl.16b v7, { v4 }, v2
; CHECK-NEXT:    tbl.16b v4, { v4 }, v3
; CHECK-NEXT:    ucvtf.4s v5, v5
; CHECK-NEXT:    ucvtf.4s v6, v6
; CHECK-NEXT:    ucvtf.4s v7, v7
; CHECK-NEXT:    ucvtf.4s v4, v4
; CHECK-NEXT:    stp q6, q5, [x9, #32]
; CHECK-NEXT:    stp q4, q7, [x9]
; CHECK-NEXT:    b.eq LBB9_1
; CHECK-NEXT:  ; %bb.2: ; %exit
; CHECK-NEXT:    ret
; CHECK-NEXT:    .loh AdrpLdr Lloh18, Lloh21
; CHECK-NEXT:    .loh AdrpLdr Lloh16, Lloh20
; CHECK-NEXT:    .loh AdrpLdr Lloh15, Lloh19
; CHECK-NEXT:    .loh AdrpAdrp Lloh14, Lloh18
; CHECK-NEXT:    .loh AdrpLdr Lloh14, Lloh17
entry:
  br label %loop

loop:
  %iv = phi i64 [ 0, %entry ], [ %iv.next, %loop ]
  %gep.src = getelementptr inbounds <16 x i8>, ptr %src, i64 %iv
  %l = load <16 x i8>, ptr %gep.src
  %conv = uitofp <16 x i8> %l to <16 x float>
  %gep.dst = getelementptr inbounds <16 x float>, ptr %dst, i64 %iv
  store <16 x float> %conv, ptr %gep.dst
  %iv.next = add i64 %iv, 1
  %ec = icmp eq i64 %iv.next, 1000
  br i1 %ec, label %loop, label %exit

exit:
  ret void
}

define void @uitofp_v8i16_to_v8f64(ptr nocapture noundef readonly %x, ptr nocapture noundef writeonly %y, i32 noundef %n) {
; CHECK-LABEL: uitofp_v8i16_to_v8f64:
; CHECK:       ; %bb.0: ; %entry
; CHECK-NEXT:  Lloh22:
; CHECK-NEXT:    adrp x8, lCPI10_0@PAGE
; CHECK-NEXT:  Lloh23:
; CHECK-NEXT:    adrp x9, lCPI10_1@PAGE
; CHECK-NEXT:  Lloh24:
; CHECK-NEXT:    adrp x10, lCPI10_2@PAGE
; CHECK-NEXT:  Lloh25:
; CHECK-NEXT:    ldr q0, [x8, lCPI10_0@PAGEOFF]
; CHECK-NEXT:  Lloh26:
; CHECK-NEXT:    adrp x8, lCPI10_3@PAGE
; CHECK-NEXT:  Lloh27:
; CHECK-NEXT:    ldr q1, [x9, lCPI10_1@PAGEOFF]
; CHECK-NEXT:  Lloh28:
; CHECK-NEXT:    ldr q2, [x10, lCPI10_2@PAGEOFF]
; CHECK-NEXT:  Lloh29:
; CHECK-NEXT:    ldr q3, [x8, lCPI10_3@PAGEOFF]
; CHECK-NEXT:    mov x8, xzr
; CHECK-NEXT:  LBB10_1: ; %vector.body
; CHECK-NEXT:    ; =>This Inner Loop Header: Depth=1
; CHECK-NEXT:    ldr q4, [x0, x8]
; CHECK-NEXT:    add x9, x1, x8
; CHECK-NEXT:    add x8, x8, #64
; CHECK-NEXT:    cmp x8, #2, lsl #12 ; =8192
; CHECK-NEXT:    tbl.16b v5, { v4 }, v0
; CHECK-NEXT:    tbl.16b v6, { v4 }, v1
; CHECK-NEXT:    tbl.16b v7, { v4 }, v2
; CHECK-NEXT:    tbl.16b v4, { v4 }, v3
; CHECK-NEXT:    ucvtf.2d v5, v5
; CHECK-NEXT:    ucvtf.2d v6, v6
; CHECK-NEXT:    ucvtf.2d v7, v7
; CHECK-NEXT:    ucvtf.2d v4, v4
; CHECK-NEXT:    stp q6, q5, [x9, #32]
; CHECK-NEXT:    stp q4, q7, [x9]
; CHECK-NEXT:    b.ne LBB10_1
; CHECK-NEXT:  ; %bb.2: ; %for.cond.cleanup
; CHECK-NEXT:    ret
; CHECK-NEXT:    .loh AdrpLdr Lloh26, Lloh29
; CHECK-NEXT:    .loh AdrpLdr Lloh24, Lloh28
; CHECK-NEXT:    .loh AdrpLdr Lloh23, Lloh27
; CHECK-NEXT:    .loh AdrpAdrp Lloh22, Lloh26
; CHECK-NEXT:    .loh AdrpLdr Lloh22, Lloh25
entry:
  br label %vector.body

vector.body:
  %index = phi i64 [ 0, %entry ], [ %index.next, %vector.body ]
  %.idx = shl nsw i64 %index, 3
  %g = getelementptr inbounds i8, ptr %x, i64 %.idx
  %wide.vec = load <8 x i16>, ptr %g, align 2
  %u = uitofp <8 x i16> %wide.vec to <8 x double>
  %h = getelementptr inbounds double, ptr %y, i64 %index
  store <8 x double> %u, ptr %h, align 8
  %index.next = add nuw i64 %index, 8
  %c = icmp eq i64 %index.next, 1024
  br i1 %c, label %for.cond.cleanup, label %vector.body

for.cond.cleanup:
  ret void
}

define void @uitofp_ld4_v32i16_to_v8f64(ptr nocapture noundef readonly %x, ptr nocapture noundef writeonly %y, i32 noundef %n) {
; CHECK-LABEL: uitofp_ld4_v32i16_to_v8f64:
; CHECK:       ; %bb.0: ; %entry
; CHECK-NEXT:  Lloh30:
; CHECK-NEXT:    adrp x8, lCPI11_0@PAGE
; CHECK-NEXT:  Lloh31:
; CHECK-NEXT:    adrp x9, lCPI11_1@PAGE
; CHECK-NEXT:  Lloh32:
; CHECK-NEXT:    adrp x10, lCPI11_2@PAGE
; CHECK-NEXT:  Lloh33:
; CHECK-NEXT:    ldr q0, [x8, lCPI11_0@PAGEOFF]
; CHECK-NEXT:  Lloh34:
; CHECK-NEXT:    adrp x8, lCPI11_3@PAGE
; CHECK-NEXT:  Lloh35:
; CHECK-NEXT:    ldr q1, [x9, lCPI11_1@PAGEOFF]
; CHECK-NEXT:  Lloh36:
; CHECK-NEXT:    ldr q2, [x10, lCPI11_2@PAGEOFF]
; CHECK-NEXT:  Lloh37:
; CHECK-NEXT:    ldr q3, [x8, lCPI11_3@PAGEOFF]
; CHECK-NEXT:    mov x8, xzr
; CHECK-NEXT:  LBB11_1: ; %vector.body
; CHECK-NEXT:    ; =>This Inner Loop Header: Depth=1
; CHECK-NEXT:    add x9, x0, x8
; CHECK-NEXT:    ldp q5, q4, [x9, #32]
; CHECK-NEXT:    ldp q7, q6, [x9]
; CHECK-NEXT:    add x9, x1, x8
; CHECK-NEXT:    add x8, x8, #64
; CHECK-NEXT:    tbl.16b v16, { v4 }, v0
; CHECK-NEXT:    tbl.16b v17, { v5 }, v0
; CHECK-NEXT:    tbl.16b v21, { v4 }, v1
; CHECK-NEXT:    tbl.16b v18, { v6 }, v0
; CHECK-NEXT:    tbl.16b v19, { v7 }, v0
; CHECK-NEXT:    tbl.16b v20, { v7 }, v1
; CHECK-NEXT:    tbl.16b v22, { v5 }, v1
; CHECK-NEXT:    tbl.16b v23, { v5 }, v2
; CHECK-NEXT:    tbl.16b v24, { v4 }, v2
; CHECK-NEXT:    tbl.16b v25, { v7 }, v2
; CHECK-NEXT:    tbl.16b v5, { v5 }, v3
; CHECK-NEXT:    tbl.16b v4, { v4 }, v3
; CHECK-NEXT:    tbl.16b v7, { v7 }, v3
; CHECK-NEXT:    tbl.16b v26, { v6 }, v1
; CHECK-NEXT:    tbl.16b v27, { v6 }, v2
; CHECK-NEXT:    tbl.16b v6, { v6 }, v3
; CHECK-NEXT:    ucvtf.2d v17, v17
; CHECK-NEXT:    ucvtf.2d v16, v16
; CHECK-NEXT:    ucvtf.2d v19, v19
; CHECK-NEXT:    ucvtf.2d v18, v18
; CHECK-NEXT:    ucvtf.2d v22, v22
; CHECK-NEXT:    ucvtf.2d v23, v23
; CHECK-NEXT:    ucvtf.2d v5, v5
; CHECK-NEXT:    ucvtf.2d v21, v21
; CHECK-NEXT:    ucvtf.2d v24, v24
; CHECK-NEXT:    ucvtf.2d v4, v4
; CHECK-NEXT:    cmp x8, #2, lsl #12 ; =8192
; CHECK-NEXT:    ucvtf.2d v20, v20
; CHECK-NEXT:    ucvtf.2d v25, v25
; CHECK-NEXT:    ucvtf.2d v7, v7
; CHECK-NEXT:    ucvtf.2d v26, v26
; CHECK-NEXT:    ucvtf.2d v27, v27
; CHECK-NEXT:    ucvtf.2d v6, v6
; CHECK-NEXT:    fadd.2d v17, v22, v17
; CHECK-NEXT:    fadd.2d v5, v23, v5
; CHECK-NEXT:    fadd.2d v16, v21, v16
; CHECK-NEXT:    fadd.2d v4, v24, v4
; CHECK-NEXT:    fadd.2d v19, v20, v19
; CHECK-NEXT:    fadd.2d v7, v25, v7
; CHECK-NEXT:    fadd.2d v18, v26, v18
; CHECK-NEXT:    fadd.2d v6, v27, v6
; CHECK-NEXT:    fadd.2d v5, v17, v5
; CHECK-NEXT:    fadd.2d v4, v16, v4
; CHECK-NEXT:    fadd.2d v7, v19, v7
; CHECK-NEXT:    fadd.2d v6, v18, v6
; CHECK-NEXT:    stp q5, q4, [x9, #32]
; CHECK-NEXT:    stp q7, q6, [x9]
; CHECK-NEXT:    b.ne LBB11_1
; CHECK-NEXT:  ; %bb.2: ; %for.cond.cleanup
; CHECK-NEXT:    ret
; CHECK-NEXT:    .loh AdrpLdr Lloh34, Lloh37
; CHECK-NEXT:    .loh AdrpLdr Lloh32, Lloh36
; CHECK-NEXT:    .loh AdrpLdr Lloh31, Lloh35
; CHECK-NEXT:    .loh AdrpAdrp Lloh30, Lloh34
; CHECK-NEXT:    .loh AdrpLdr Lloh30, Lloh33
entry:
  br label %vector.body

vector.body:
  %index = phi i64 [ 0, %entry ], [ %index.next, %vector.body ]
  %.idx = shl nsw i64 %index, 3
  %0 = getelementptr inbounds i8, ptr %x, i64 %.idx
  %wide.vec = load <32 x i16>, ptr %0, align 2
  %strided.vec = shufflevector <32 x i16> %wide.vec, <32 x i16> poison, <8 x i32> <i32 0, i32 4, i32 8, i32 12, i32 16, i32 20, i32 24, i32 28>
  %strided.vec36 = shufflevector <32 x i16> %wide.vec, <32 x i16> poison, <8 x i32> <i32 1, i32 5, i32 9, i32 13, i32 17, i32 21, i32 25, i32 29>
  %strided.vec37 = shufflevector <32 x i16> %wide.vec, <32 x i16> poison, <8 x i32> <i32 2, i32 6, i32 10, i32 14, i32 18, i32 22, i32 26, i32 30>
  %strided.vec38 = shufflevector <32 x i16> %wide.vec, <32 x i16> poison, <8 x i32> <i32 3, i32 7, i32 11, i32 15, i32 19, i32 23, i32 27, i32 31>
  %1 = uitofp <8 x i16> %strided.vec to <8 x double>
  %2 = uitofp <8 x i16> %strided.vec36 to <8 x double>
  %3 = fadd fast <8 x double> %2, %1
  %4 = uitofp <8 x i16> %strided.vec37 to <8 x double>
  %5 = fadd fast <8 x double> %3, %4
  %6 = uitofp <8 x i16> %strided.vec38 to <8 x double>
  %7 = fadd fast <8 x double> %5, %6
  %8 = getelementptr inbounds double, ptr %y, i64 %index
  store <8 x double> %7, ptr %8, align 8
  %index.next = add nuw i64 %index, 8
  %9 = icmp eq i64 %index.next, 1024
  br i1 %9, label %for.cond.cleanup, label %vector.body

for.cond.cleanup:
  ret void
}

