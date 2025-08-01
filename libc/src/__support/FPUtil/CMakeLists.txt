add_header_library(
  fenv_impl
  HDRS
    FEnvImpl.h
  DEPENDS
    libc.hdr.types.fenv_t
    libc.hdr.fenv_macros
    libc.hdr.math_macros
    libc.src.__support.macros.attributes
    libc.src.errno.errno
)

add_header_library(
  rounding_mode
  HDRS
    rounding_mode.h
  DEPENDS
    libc.hdr.fenv_macros
    libc.src.__support.macros.attributes
    libc.src.__support.macros.properties.architectures
    libc.src.__support.macros.sanitizer
    libc.src.errno.errno
)

add_header_library(
  fp_bits
  HDRS
    FPBits.h
  DEPENDS
    libc.src.__support.common
    libc.src.__support.CPP.bit
    libc.src.__support.CPP.type_traits
    libc.src.__support.libc_assert
    libc.src.__support.macros.attributes
    libc.src.__support.macros.properties.types
    libc.src.__support.math_extras
    libc.src.__support.sign
    libc.src.__support.uint128
)

add_header_library(
  fpbits_str
  HDRS
    fpbits_str.h
  DEPENDS
    .fp_bits
    libc.src.__support.CPP.bit
    libc.src.__support.CPP.type_traits
    libc.src.__support.macros.attributes
    libc.src.__support.common
    libc.src.__support.integer_to_string
)

add_header_library(
  nearest_integer_operations
  HDRS
    NearestIntegerOperations.h
  DEPENDS
    .fp_bits
    .fenv_impl
    .rounding_mode
    libc.hdr.math_macros
    libc.src.__support.CPP.type_traits
    libc.src.__support.common
    libc.src.errno.errno
)

add_header_library(
  normal_float
  HDRS
    NormalFloat.h
  DEPENDS
    .fp_bits
    libc.src.__support.CPP.type_traits
    libc.src.__support.common
)

add_header_library(
  division_and_remainder_operations
  HDRS
    DivisionAndRemainderOperations.h
  DEPENDS
    .fp_bits
    .manipulation_functions
    .normal_float
    libc.src.__support.CPP.type_traits
    libc.src.__support.common
)

add_header_library(
  except_value_utils
  HDRS
    except_value_utils.h
  DEPENDS
    .cast
    .fp_bits
    .fenv_impl
    .rounding_mode
    libc.src.__support.CPP.optional
    libc.src.__support.macros.optimization
    libc.src.__support.macros.properties.cpu_features
    libc.src.__support.macros.properties.types
)


add_header_library(
  sqrt
  HDRS
    sqrt.h
  DEPENDS
    libc.src.__support.common
    libc.src.__support.FPUtil.generic.sqrt
    libc.src.__support.macros.properties.cpu_features
)

add_header_library(
  fma
  HDRS
    FMA.h
  DEPENDS
    libc.src.__support.common
    libc.src.__support.CPP.type_traits
    libc.src.__support.FPUtil.generic.fma
    libc.src.__support.macros.properties.cpu_features
  FLAGS
    FMA_OPT
)

add_header_library(
  multiply_add
  HDRS
    multiply_add.h
  DEPENDS
    libc.src.__support.common
    libc.src.__support.macros.properties.cpu_features
  FLAGS
    FMA_OPT
)

add_header_library(
  polyeval
  HDRS
    PolyEval.h
  DEPENDS
    .multiply_add
    libc.src.__support.common
)

add_header_library(
  nearest_integer
  HDRS
    nearest_integer.h
  DEPENDS
    libc.src.__support.common
    libc.src.__support.macros.optimization
    libc.src.__support.macros.properties.cpu_features
  FLAGS
    ROUND_OPT
)

add_header_library(
  double_double
  HDRS
    double_double.h
  DEPENDS
    libc.src.__support.common
    libc.src.__support.number_pair
    libc.src.__support.macros.properties.cpu_features
    .multiply_add
)

add_header_library(
  triple_double
  HDRS
    triple_double.h
)

add_header_library(
  dyadic_float
  HDRS
    dyadic_float.h
  DEPENDS
    .fenv_impl
    .fp_bits
    .multiply_add
    .rounding_mode
    libc.hdr.errno_macros
    libc.hdr.fenv_macros
    libc.src.__support.CPP.type_traits
    libc.src.__support.big_int
    libc.src.__support.macros.optimization
    libc.src.__support.macros.properties.types
)

add_header_library(
  basic_operations
  HDRS
    BasicOperations.h
  DEPENDS
    .dyadic_float
    .fp_bits
    .fenv_impl
    libc.src.__support.CPP.type_traits
    libc.src.__support.big_int
    libc.src.__support.uint128
    libc.src.__support.common
    libc.src.__support.macros.optimization
    libc.src.__support.macros.properties.architectures
    libc.src.__support.macros.properties.types
)

add_header_library(
  comparison_operations
  HDRS
    comparison_operations.h
  DEPENDS
    .fenv_impl
    .fp_bits
    libc.src.__support.CPP.type_traits
    libc.src.__support.macros.config
)

add_header_library(
  hypot
  HDRS
    Hypot.h
  DEPENDS
    .basic_operations
    .fenv_impl
    .fp_bits
    .rounding_mode
    libc.src.__support.common
    libc.src.__support.CPP.bit
    libc.src.__support.CPP.type_traits
    libc.src.__support.uint128
)

add_header_library(
  manipulation_functions
  HDRS
    ManipulationFunctions.h
  DEPENDS
    .cast
    .dyadic_float
    .fenv_impl
    .fp_bits
    .nearest_integer_operations
    .normal_float
    libc.hdr.math_macros
    libc.src.errno.errno
    libc.src.__support.common
    libc.src.__support.CPP.bit
    libc.src.__support.CPP.limits
    libc.src.__support.CPP.type_traits
    libc.src.__support.macros.optimization
)

add_header_library(
  cast
  HDRS
    cast.h
  DEPENDS
    .dyadic_float
    .fp_bits
    libc.hdr.fenv_macros
    libc.src.__support.CPP.algorithm
    libc.src.__support.CPP.type_traits
    libc.src.__support.macros.properties.types
)

add_header_library(
  bfloat16
  HDRS
    bfloat16.h
  DEPENDS
    .cast
    .comparison_operations
    .dyadic_float
    libc.src.__support.CPP.bit
    libc.src.__support.CPP.type_traits
    libc.src.__support.macros.config
    libc.src.__support.macros.properties.types
)

add_subdirectory(generic)
