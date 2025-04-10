//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef _LIBCPP___CXX03___ALGORITHM_RANGES_PUSH_HEAP_H
#define _LIBCPP___CXX03___ALGORITHM_RANGES_PUSH_HEAP_H

#include <__cxx03/__algorithm/iterator_operations.h>
#include <__cxx03/__algorithm/make_projected.h>
#include <__cxx03/__algorithm/push_heap.h>
#include <__cxx03/__concepts/same_as.h>
#include <__cxx03/__config>
#include <__cxx03/__functional/identity.h>
#include <__cxx03/__functional/invoke.h>
#include <__cxx03/__functional/ranges_operations.h>
#include <__cxx03/__iterator/concepts.h>
#include <__cxx03/__iterator/iterator_traits.h>
#include <__cxx03/__iterator/next.h>
#include <__cxx03/__iterator/projected.h>
#include <__cxx03/__iterator/sortable.h>
#include <__cxx03/__ranges/access.h>
#include <__cxx03/__ranges/concepts.h>
#include <__cxx03/__ranges/dangling.h>
#include <__cxx03/__utility/forward.h>
#include <__cxx03/__utility/move.h>

#if !defined(_LIBCPP_HAS_NO_PRAGMA_SYSTEM_HEADER)
#  pragma GCC system_header
#endif

_LIBCPP_PUSH_MACROS
#include <__cxx03/__undef_macros>

#if _LIBCPP_STD_VER >= 20

_LIBCPP_BEGIN_NAMESPACE_STD

namespace ranges {
namespace __push_heap {

struct __fn {
  template <class _Iter, class _Sent, class _Comp, class _Proj>
  _LIBCPP_HIDE_FROM_ABI constexpr static _Iter
  __push_heap_fn_impl(_Iter __first, _Sent __last, _Comp& __comp, _Proj& __proj) {
    auto __last_iter = ranges::next(__first, __last);

    auto&& __projected_comp = std::__make_projected(__comp, __proj);
    std::__push_heap<_RangeAlgPolicy>(std::move(__first), __last_iter, __projected_comp);

    return __last_iter;
  }

  template <random_access_iterator _Iter, sentinel_for<_Iter> _Sent, class _Comp = ranges::less, class _Proj = identity>
    requires sortable<_Iter, _Comp, _Proj>
  _LIBCPP_HIDE_FROM_ABI constexpr _Iter
  operator()(_Iter __first, _Sent __last, _Comp __comp = {}, _Proj __proj = {}) const {
    return __push_heap_fn_impl(std::move(__first), std::move(__last), __comp, __proj);
  }

  template <random_access_range _Range, class _Comp = ranges::less, class _Proj = identity>
    requires sortable<iterator_t<_Range>, _Comp, _Proj>
  _LIBCPP_HIDE_FROM_ABI constexpr borrowed_iterator_t<_Range>
  operator()(_Range&& __r, _Comp __comp = {}, _Proj __proj = {}) const {
    return __push_heap_fn_impl(ranges::begin(__r), ranges::end(__r), __comp, __proj);
  }
};

} // namespace __push_heap

inline namespace __cpo {
inline constexpr auto push_heap = __push_heap::__fn{};
} // namespace __cpo
} // namespace ranges

_LIBCPP_END_NAMESPACE_STD

#endif // _LIBCPP_STD_VER >= 20

_LIBCPP_POP_MACROS

#endif // _LIBCPP___CXX03___ALGORITHM_RANGES_PUSH_HEAP_H
