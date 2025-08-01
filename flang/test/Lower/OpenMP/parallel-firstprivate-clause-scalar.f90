! This test checks lowering of `FIRSTPRIVATE` clause for scalar types.

! REQUIRES: x86-registered-target
! REQUIRES: shell
! RUN: bbc -target x86_64-unknown-linux-gnu -fopenmp -emit-hlfir %s -o - \
! RUN: | FileCheck %s --check-prefixes=CHECK%if target=x86_64{{.*}} %{,CHECK-KIND10%}%if flang-supports-f128-math %{,CHECK-KIND16%}

!CHECK:  omp.private {type = firstprivate} @[[ARG2_LOGICAL_PRIVATIZER:_QFfirstprivate_logicalEarg2_firstprivate_l8]] : !fir.logical<1>

!CHECK:  omp.private {type = firstprivate} @[[ARG1_LOGICAL_PRIVATIZER:_QFfirstprivate_logicalEarg1_firstprivate_l32]] : !fir.logical<4> copy {
!CHECK:  ^bb0(%[[ORIG_REF:.*]]: !fir.ref<!fir.logical<4>>, %[[PVT_REF:.*]]: !fir.ref<!fir.logical<4>>):
!CHECK:    %[[ORIG_VAL:.*]] = fir.load %[[ORIG_REF]] : {{.*}}
!CHECK:    hlfir.assign %[[ORIG_VAL]] to %[[PVT_REF]] {{.*}}
!CHECK:    omp.yield(%[[PVT_REF]] : !fir.ref<!fir.logical<4>>)
!CHECK:  }

!CHECK:  omp.private {type = firstprivate} @[[ARG2_COMPLEX_PRIVATIZER:_QFfirstprivate_complexEarg2_firstprivate_z64]] : complex<f64>

!CHECK:  omp.private {type = firstprivate} @[[ARG1_COMPLEX_PRIVATIZER:_QFfirstprivate_complexEarg1_firstprivate_z32]] : complex<f32> copy {
!CHECK:  ^bb0(%[[ORIG_REF:.*]]: !fir.ref<complex<f32>>, %[[PVT_REF:.*]]: !fir.ref<complex<f32>>):
!CHECK:    %[[ORIG_VAL:.*]] = fir.load %[[ORIG_REF]] : {{.*}}
!CHECK:    hlfir.assign %[[ORIG_VAL]] to %[[PVT_REF]] {{.*}}
!CHECK:    omp.yield(%[[PVT_REF]] : !fir.ref<complex<f32>>)
!CHECK:  }

!CHECK-DAG: func @_QPfirstprivate_complex(%[[ARG1:.*]]: !fir.ref<complex<f32>>{{.*}}, %[[ARG2:.*]]: !fir.ref<complex<f64>>{{.*}}) {
!CHECK:    %[[ARG1_DECL:.*]]:2 = hlfir.declare %[[ARG1]] dummy_scope %{{[0-9]+}} {uniq_name = "_QFfirstprivate_complexEarg1"} : (!fir.ref<complex<f32>>, !fir.dscope) -> (!fir.ref<complex<f32>>, !fir.ref<complex<f32>>)
!CHECK:    %[[ARG2_DECL:.*]]:2 = hlfir.declare %[[ARG2]] dummy_scope %{{[0-9]+}} {uniq_name = "_QFfirstprivate_complexEarg2"} : (!fir.ref<complex<f64>>, !fir.dscope) -> (!fir.ref<complex<f64>>, !fir.ref<complex<f64>>)
!CHECK:   omp.parallel private(@[[ARG1_COMPLEX_PRIVATIZER]] %{{.*}}#0 -> %[[ARG1_PVT:.*]], @[[ARG2_COMPLEX_PRIVATIZER]] %{{.*}}#0 -> %[[ARG2_PVT:.*]] : {{.*}}) {
!CHECK:     %[[ARG1_PVT_DECL:.*]]:2 = hlfir.declare %[[ARG1_PVT]] {uniq_name = "_QFfirstprivate_complexEarg1"} : (!fir.ref<complex<f32>>) -> (!fir.ref<complex<f32>>, !fir.ref<complex<f32>>)
!CHECK:     %[[ARG2_PVT_DECL:.*]]:2 = hlfir.declare %[[ARG2_PVT]] {uniq_name = "_QFfirstprivate_complexEarg2"} : (!fir.ref<complex<f64>>) -> (!fir.ref<complex<f64>>, !fir.ref<complex<f64>>)
!CHECK:     fir.call @_QPfoo(%[[ARG1_PVT_DECL]]#0, %[[ARG2_PVT_DECL]]#0) {{.*}}: (!fir.ref<complex<f32>>, !fir.ref<complex<f64>>) -> ()
!CHECK:     omp.terminator
!CHECK:   }

subroutine firstprivate_complex(arg1, arg2)
        complex(4) :: arg1
        complex(8) :: arg2

!$OMP PARALLEL FIRSTPRIVATE(arg1, arg2)
        call foo(arg1, arg2)
!$OMP END PARALLEL

end subroutine

!CHECK-DAG: func @_QPfirstprivate_integer(%[[ARG1:.*]]: !fir.ref<i32>{{.*}}, %[[ARG2:.*]]: !fir.ref<i8>{{.*}}, %[[ARG3:.*]]: !fir.ref<i16>{{.*}}, %[[ARG4:.*]]: !fir.ref<i32>{{.*}}, %[[ARG5:.*]]: !fir.ref<i64>{{.*}}, %[[ARG6:.*]]: !fir.ref<i128>{{.*}}) {
!CHECK:  %[[ARG1_DECL:.*]]:2 = hlfir.declare %[[ARG1]] dummy_scope %{{[0-9]+}} {uniq_name = "_QFfirstprivate_integerEarg1"} : (!fir.ref<i32>, !fir.dscope) -> (!fir.ref<i32>, !fir.ref<i32>)
!CHECK:  %[[ARG2_DECL:.*]]:2 = hlfir.declare %[[ARG2]] dummy_scope %{{[0-9]+}} {uniq_name = "_QFfirstprivate_integerEarg2"} : (!fir.ref<i8>, !fir.dscope) -> (!fir.ref<i8>, !fir.ref<i8>)
!CHECK:  %[[ARG3_DECL:.*]]:2 = hlfir.declare %[[ARG3]] dummy_scope %{{[0-9]+}} {uniq_name = "_QFfirstprivate_integerEarg3"} : (!fir.ref<i16>, !fir.dscope) -> (!fir.ref<i16>, !fir.ref<i16>)
!CHECK:  %[[ARG4_DECL:.*]]:2 = hlfir.declare %[[ARG4]] dummy_scope %{{[0-9]+}} {uniq_name = "_QFfirstprivate_integerEarg4"} : (!fir.ref<i32>, !fir.dscope) -> (!fir.ref<i32>, !fir.ref<i32>)
!CHECK:  %[[ARG5_DECL:.*]]:2 = hlfir.declare %[[ARG5]] dummy_scope %{{[0-9]+}} {uniq_name = "_QFfirstprivate_integerEarg5"} : (!fir.ref<i64>, !fir.dscope) -> (!fir.ref<i64>, !fir.ref<i64>)
!CHECK:  %[[ARG6_DECL:.*]]:2 = hlfir.declare %[[ARG6]] dummy_scope %{{[0-9]+}} {uniq_name = "_QFfirstprivate_integerEarg6"} : (!fir.ref<i128>, !fir.dscope) -> (!fir.ref<i128>, !fir.ref<i128>)
!CHECK:  omp.parallel private({{.*firstprivate.*}} {{.*}}#0 -> %[[ARG1_PVT:.*]], {{.*firstprivate.*}} {{.*}}#0 -> %[[ARG2_PVT:.*]], {{.*firstprivate.*}} {{.*}}#0 -> %[[ARG3_PVT:.*]], {{.*firstprivate.*}} {{.*}}#0 -> %[[ARG4_PVT:.*]], {{.*firstprivate.*}} {{.*}}#0 -> %[[ARG5_PVT:.*]], {{.*firstprivate.*}} {{.*}}#0 -> %[[ARG6_PVT:.*]] : {{.*}}) {
!CHECK:    %[[ARG1_PVT_DECL:.*]]:2 = hlfir.declare %[[ARG1_PVT]] {uniq_name = "_QFfirstprivate_integerEarg1"} : (!fir.ref<i32>) -> (!fir.ref<i32>, !fir.ref<i32>)
!CHECK:    %[[ARG2_PVT_DECL:.*]]:2 = hlfir.declare %[[ARG2_PVT]] {uniq_name = "_QFfirstprivate_integerEarg2"} : (!fir.ref<i8>) -> (!fir.ref<i8>, !fir.ref<i8>)
!CHECK:    %[[ARG3_PVT_DECL:.*]]:2 = hlfir.declare %[[ARG3_PVT]] {uniq_name = "_QFfirstprivate_integerEarg3"} : (!fir.ref<i16>) -> (!fir.ref<i16>, !fir.ref<i16>)
!CHECK:    %[[ARG4_PVT_DECL:.*]]:2 = hlfir.declare %[[ARG4_PVT]] {uniq_name = "_QFfirstprivate_integerEarg4"} : (!fir.ref<i32>) -> (!fir.ref<i32>, !fir.ref<i32>)
!CHECK:    %[[ARG5_PVT_DECL:.*]]:2 = hlfir.declare %[[ARG5_PVT]] {uniq_name = "_QFfirstprivate_integerEarg5"} : (!fir.ref<i64>) -> (!fir.ref<i64>, !fir.ref<i64>)
!CHECK:    %[[ARG6_PVT_DECL:.*]]:2 = hlfir.declare %[[ARG6_PVT]] {uniq_name = "_QFfirstprivate_integerEarg6"} : (!fir.ref<i128>) -> (!fir.ref<i128>, !fir.ref<i128>)
!CHECK:    fir.call @_QPbar(%[[ARG1_PVT_DECL]]#0, %[[ARG2_PVT_DECL]]#0, %[[ARG3_PVT_DECL]]#0, %[[ARG4_PVT_DECL]]#0,
!%[[ARG5_PVT_DECL]]#0, %[[ARG6_PVT_DECL]]#0) {{.*}}: (!fir.ref<i32>, !fir.ref<i8>, !fir.ref<i16>, !fir.ref<i32>, !fir.ref<i64>, !fir.ref<i128>) -> ()
!CHECK:    omp.terminator
!CHECK:  }

subroutine firstprivate_integer(arg1, arg2, arg3, arg4, arg5, arg6)
        integer :: arg1
        integer(kind=1) :: arg2
        integer(kind=2) :: arg3
        integer(kind=4) :: arg4
        integer(kind=8) :: arg5
        integer(kind=16) :: arg6

!$OMP PARALLEL FIRSTPRIVATE(arg1, arg2, arg3, arg4, arg5, arg6)
        call bar(arg1, arg2, arg3, arg4, arg5, arg6)
!$OMP END PARALLEL

end subroutine

!CHECK-DAG: func @_QPfirstprivate_logical(%[[ARG1:.*]]: !fir.ref<!fir.logical<4>>{{.*}}, %[[ARG2:.*]]: !fir.ref<!fir.logical<1>>{{.*}}, %[[ARG3:.*]]: !fir.ref<!fir.logical<2>>{{.*}}, %[[ARG4:.*]]: !fir.ref<!fir.logical<4>>{{.*}}, %[[ARG5:.*]]: !fir.ref<!fir.logical<8>>{{.*}}) {
!CHECK:    %[[ARG1_DECL:.*]]:2 = hlfir.declare %[[ARG1]] dummy_scope %{{[0-9]+}} {uniq_name = "_QFfirstprivate_logicalEarg1"} : (!fir.ref<!fir.logical<4>>, !fir.dscope) -> (!fir.ref<!fir.logical<4>>, !fir.ref<!fir.logical<4>>)
!CHECK:    %[[ARG2_DECL:.*]]:2 = hlfir.declare %[[ARG2]] dummy_scope %{{[0-9]+}} {uniq_name = "_QFfirstprivate_logicalEarg2"} : (!fir.ref<!fir.logical<1>>, !fir.dscope) -> (!fir.ref<!fir.logical<1>>, !fir.ref<!fir.logical<1>>)
!CHECK:    %[[ARG3_DECL:.*]]:2 = hlfir.declare %[[ARG3]] dummy_scope %{{[0-9]+}} {uniq_name = "_QFfirstprivate_logicalEarg3"} : (!fir.ref<!fir.logical<2>>, !fir.dscope) -> (!fir.ref<!fir.logical<2>>, !fir.ref<!fir.logical<2>>)
!CHECK:    %[[ARG4_DECL:.*]]:2 = hlfir.declare %[[ARG4]] dummy_scope %{{[0-9]+}} {uniq_name = "_QFfirstprivate_logicalEarg4"} : (!fir.ref<!fir.logical<4>>, !fir.dscope) -> (!fir.ref<!fir.logical<4>>, !fir.ref<!fir.logical<4>>)
!CHECK:    %[[ARG5_DECL:.*]]:2 = hlfir.declare %[[ARG5]] dummy_scope %{{[0-9]+}} {uniq_name = "_QFfirstprivate_logicalEarg5"} : (!fir.ref<!fir.logical<8>>, !fir.dscope) -> (!fir.ref<!fir.logical<8>>, !fir.ref<!fir.logical<8>>)
!CHECK:  omp.parallel private(@[[ARG1_LOGICAL_PRIVATIZER]] {{.*}}#0 -> %[[ARG1_PVT:.*]], @[[ARG2_LOGICAL_PRIVATIZER]] {{.*}}#0 -> %[[ARG2_PVT:.*]], {{.*firstprivate.*}} {{.*}}#0 -> %[[ARG3_PVT:.*]], {{.*firstprivate.*}} {{.*}}#0 -> %[[ARG4_PVT:.*]], {{.*firstprivate.*}} {{.*}}#0 -> %[[ARG5_PVT:.*]] : {{.*}}) {
!CHECK:     %[[ARG1_PVT_DECL:.*]]:2 = hlfir.declare %[[ARG1_PVT]] {uniq_name = "_QFfirstprivate_logicalEarg1"} : (!fir.ref<!fir.logical<4>>) -> (!fir.ref<!fir.logical<4>>, !fir.ref<!fir.logical<4>>)
!CHECK:     %[[ARG2_PVT_DECL:.*]]:2 = hlfir.declare %[[ARG2_PVT]] {uniq_name = "_QFfirstprivate_logicalEarg2"} : (!fir.ref<!fir.logical<1>>) -> (!fir.ref<!fir.logical<1>>, !fir.ref<!fir.logical<1>>)
!CHECK:     %[[ARG3_PVT_DECL:.*]]:2 = hlfir.declare %[[ARG3_PVT]] {uniq_name = "_QFfirstprivate_logicalEarg3"} : (!fir.ref<!fir.logical<2>>) -> (!fir.ref<!fir.logical<2>>, !fir.ref<!fir.logical<2>>)
!CHECK:     %[[ARG4_PVT_DECL:.*]]:2 = hlfir.declare %[[ARG4_PVT]] {uniq_name = "_QFfirstprivate_logicalEarg4"} : (!fir.ref<!fir.logical<4>>) -> (!fir.ref<!fir.logical<4>>, !fir.ref<!fir.logical<4>>)
!CHECK:     %[[ARG5_PVT_DECL:.*]]:2 = hlfir.declare %[[ARG5_PVT]] {uniq_name = "_QFfirstprivate_logicalEarg5"} : (!fir.ref<!fir.logical<8>>) -> (!fir.ref<!fir.logical<8>>, !fir.ref<!fir.logical<8>>)
!CHECK:     fir.call @_QPbaz(%[[ARG1_PVT_DECL]]#0, %[[ARG2_PVT_DECL]]#0, %[[ARG3_PVT_DECL]]#0, %[[ARG4_PVT_DECL]]#0, %[[ARG5_PVT_DECL]]#0) {{.*}}: (!fir.ref<!fir.logical<4>>, !fir.ref<!fir.logical<1>>, !fir.ref<!fir.logical<2>>, !fir.ref<!fir.logical<4>>, !fir.ref<!fir.logical<8>>) -> ()
!CHECK:     omp.terminator
!CHECK:   }

subroutine firstprivate_logical(arg1, arg2, arg3, arg4, arg5)
        logical :: arg1
        logical(kind=1) :: arg2
        logical(kind=2) :: arg3
        logical(kind=4) :: arg4
        logical(kind=8) :: arg5

!$OMP PARALLEL FIRSTPRIVATE(arg1, arg2, arg3, arg4, arg5)
        call baz(arg1, arg2, arg3, arg4, arg5)
!$OMP END PARALLEL

end subroutine

!CHECK-LABEL: func @_QPfirstprivate_real(
!CHECK-SAME: %[[ARG1:.*]]: !fir.ref<f32>{{.*}}, %[[ARG2:.*]]: !fir.ref<f16>{{.*}}, %[[ARG3:.*]]: !fir.ref<f32>{{.*}}, %[[ARG4:.*]]: !fir.ref<f64>{{.*}}) {
!CHECK:   %[[ARG1_DECL:.*]]:2 = hlfir.declare %[[ARG1]] dummy_scope %{{[0-9]+}} {uniq_name = "_QFfirstprivate_realEarg1"} : (!fir.ref<f32>, !fir.dscope) -> (!fir.ref<f32>, !fir.ref<f32>)
!CHECK:   %[[ARG2_DECL:.*]]:2 = hlfir.declare %[[ARG2]] dummy_scope %{{[0-9]+}} {uniq_name = "_QFfirstprivate_realEarg2"} : (!fir.ref<f16>, !fir.dscope) -> (!fir.ref<f16>, !fir.ref<f16>)
!CHECK:   %[[ARG3_DECL:.*]]:2 = hlfir.declare %[[ARG3]] dummy_scope %{{[0-9]+}} {uniq_name = "_QFfirstprivate_realEarg3"} : (!fir.ref<f32>, !fir.dscope) -> (!fir.ref<f32>, !fir.ref<f32>)
!CHECK:   %[[ARG4_DECL:.*]]:2 = hlfir.declare %[[ARG4]] dummy_scope %{{[0-9]+}} {uniq_name = "_QFfirstprivate_realEarg4"} : (!fir.ref<f64>, !fir.dscope) -> (!fir.ref<f64>, !fir.ref<f64>)
!CHECK:  omp.parallel private({{.*firstprivate.*}} {{.*}}#0 -> %[[ARG1_PVT:.*]], {{.*firstprivate.*}} {{.*}}#0 -> %[[ARG2_PVT:.*]], {{.*firstprivate.*}} {{.*}}#0 -> %[[ARG3_PVT:.*]], {{.*firstprivate.*}} {{.*}}#0 -> %[[ARG4_PVT:.*]] : {{.*}}) {
!CHECK:     %[[ARG1_PVT_DECL:.*]]:2 = hlfir.declare %[[ARG1_PVT]] {uniq_name = "_QFfirstprivate_realEarg1"} : (!fir.ref<f32>) -> (!fir.ref<f32>, !fir.ref<f32>)
!CHECK:     %[[ARG2_PVT_DECL:.*]]:2 = hlfir.declare %[[ARG2_PVT]] {uniq_name = "_QFfirstprivate_realEarg2"} : (!fir.ref<f16>) -> (!fir.ref<f16>, !fir.ref<f16>)
!CHECK:     %[[ARG3_PVT_DECL:.*]]:2 = hlfir.declare %[[ARG3_PVT]] {uniq_name = "_QFfirstprivate_realEarg3"} : (!fir.ref<f32>) -> (!fir.ref<f32>, !fir.ref<f32>)
!CHECK:     %[[ARG4_PVT_DECL:.*]]:2 = hlfir.declare %[[ARG4_PVT]] {uniq_name = "_QFfirstprivate_realEarg4"} : (!fir.ref<f64>) -> (!fir.ref<f64>, !fir.ref<f64>)
!CHECK:     fir.call @_QPqux(%[[ARG1_PVT_DECL]]#0, %[[ARG2_PVT_DECL]]#0, %[[ARG3_PVT_DECL]]#0, %[[ARG4_PVT_DECL]]#0) {{.*}}: (!fir.ref<f32>, !fir.ref<f16>, !fir.ref<f32>, !fir.ref<f64>) -> ()
!CHECK:     omp.terminator
!CHECK:   }
subroutine firstprivate_real(arg1, arg2, arg3, arg4, arg5, arg6)
        real :: arg1
        real(kind=2) :: arg2
        real(kind=4) :: arg3
        real(kind=8) :: arg4

!$OMP PARALLEL FIRSTPRIVATE(arg1, arg2, arg3, arg4)
        call qux(arg1, arg2, arg3, arg4)
!$OMP END PARALLEL

end subroutine

!CHECK-KIND10-LABEL: func @_QPfirstprivate_real10(
!CHECK-KIND10-SAME: %[[ARG1:.*]]: !fir.ref<f80>{{.*}}) {
!CHECK-KIND10:   %[[ARG1_DECL:.*]]:2 = hlfir.declare %[[ARG1]] dummy_scope %{{[0-9]+}} {uniq_name = "_QFfirstprivate_real10Earg1"} : (!fir.ref<f80>, !fir.dscope) -> (!fir.ref<f80>, !fir.ref<f80>)
!CHECK-KIND10:  omp.parallel private({{.*firstprivate.*}} {{.*}}#0 -> %[[ARG1_PVT:.*]] : {{.*}}) {
!CHECK-KIND10:     %[[ARG1_PVT_DECL:.*]]:2 = hlfir.declare %[[ARG1_PVT]] {uniq_name = "_QFfirstprivate_real10Earg1"} : (!fir.ref<f80>) -> (!fir.ref<f80>, !fir.ref<f80>)
!CHECK-KIND10:     fir.call @_QPqux10(%[[ARG1_PVT_DECL]]#0) {{.*}} : (!fir.ref<f80>) -> ()
!CHECK-KIND10:     omp.terminator
!CHECK-KIND10:   }
subroutine firstprivate_real10(arg1)
        integer, parameter :: kind10 = merge(10, 4, selected_real_kind(p=18).eq.10)
        real(kind=kind10) :: arg1
!$OMP PARALLEL FIRSTPRIVATE(arg1)
        call qux10(arg1)
!$OMP END PARALLEL
end subroutine

!CHECK-KIND16-LABEL: func @_QPfirstprivate_real16(
!CHECK-KIND16-SAME: %[[ARG1:.*]]: !fir.ref<f128>{{.*}}) {
!CHECK-KIND16:   %[[ARG1_DECL:.*]]:2 = hlfir.declare %[[ARG1]] dummy_scope %{{[0-9]+}} {uniq_name = "_QFfirstprivate_real16Earg1"} : (!fir.ref<f128>, !fir.dscope) -> (!fir.ref<f128>, !fir.ref<f128>)
!CHECK-KIND16:  omp.parallel private({{.*firstprivate.*}} {{.*}}#0 -> %[[ARG1_PVT:.*]] : {{.*}}) {
!CHECK-KIND16:     %[[ARG1_PVT_DECL:.*]]:2 = hlfir.declare %[[ARG1_PVT]] {uniq_name = "_QFfirstprivate_real16Earg1"} : (!fir.ref<f128>) -> (!fir.ref<f128>, !fir.ref<f128>)
!CHECK-KIND16:     fir.call @_QPqux16(%[[ARG1_PVT_DECL]]#0) {{.*}} : (!fir.ref<f128>) -> ()
!CHECK-KIND16:     omp.terminator
!CHECK-KIND16:   }
subroutine firstprivate_real16(arg1)
        integer, parameter :: kind16 = merge(16, 4, selected_real_kind(p=33).eq.16)
        real(kind=kind16) :: arg1
!$OMP PARALLEL FIRSTPRIVATE(arg1)
        call qux16(arg1)
!$OMP END PARALLEL
end subroutine

!CHECK-LABEL:   func.func @_QPmultiple_firstprivate(
!CHECK-SAME:                                        %[[A_ADDR:.*]]: !fir.ref<i32> {fir.bindc_name = "a"},
!CHECK-SAME:                                        %[[B_ADDR:.*]]: !fir.ref<i32> {fir.bindc_name = "b"}) {
!CHECK:           %[[A_DECL:.*]]:2 = hlfir.declare %[[A_ADDR]] dummy_scope %{{[0-9]+}} {uniq_name = "_QFmultiple_firstprivateEa"} : (!fir.ref<i32>, !fir.dscope) -> (!fir.ref<i32>, !fir.ref<i32>)
!CHECK:           %[[B_DECL:.*]]:2 = hlfir.declare %[[B_ADDR]] dummy_scope %{{[0-9]+}} {uniq_name = "_QFmultiple_firstprivateEb"} : (!fir.ref<i32>, !fir.dscope) -> (!fir.ref<i32>, !fir.ref<i32>)
!CHECK:  omp.parallel private({{.*firstprivate.*}} {{.*}}#0 -> %[[A_PRIV_ADDR:.*]], {{.*firstprivate.*}} {{.*}}#0 -> %[[B_PRIV_ADDR:.*]] : {{.*}}) {
!CHECK:             %[[A_PRIV_DECL:.*]]:2 = hlfir.declare %[[A_PRIV_ADDR]] {uniq_name = "_QFmultiple_firstprivateEa"} : (!fir.ref<i32>) -> (!fir.ref<i32>, !fir.ref<i32>)
!CHECK:             %[[B_PRIV_DECL:.*]]:2 = hlfir.declare %[[B_PRIV_ADDR]] {uniq_name = "_QFmultiple_firstprivateEb"} : (!fir.ref<i32>) -> (!fir.ref<i32>, !fir.ref<i32>)
!CHECK:             fir.call @_QPquux(%[[A_PRIV_DECL]]#0, %[[B_PRIV_DECL]]#0) {{.*}}: (!fir.ref<i32>, !fir.ref<i32>) -> ()
!CHECK:             omp.terminator
!CHECK:           }
!CHECK:           return
!CHECK:         }

subroutine multiple_firstprivate(a, b)
        integer :: a, b
!$OMP PARALLEL FIRSTPRIVATE(a) FIRSTPRIVATE(b)
        call quux(a, b)
!$OMP END PARALLEL
end subroutine multiple_firstprivate
