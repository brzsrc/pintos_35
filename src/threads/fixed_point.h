#ifndef _FIXED_POINT_H
#define _FIXED_POINT_H

#include <inttypes.h>
#define SHIFT_AMOUNT 14

typedef int32_t fixed_t;

// TYPE: X,Y: FLOAT; N: INT.

// Convert n to fixed point.
#define FLOAT(N) ((fixed_t)(N) << SHIFT_AMOUNT)
// Round x to integer toward zero.
#define ROUND_ZERO(X) ((X) >> SHIFT_AMOUNT);
// Rounding x to nearest integer.
#define ROUND_NEAR(X)                                             \
  ((X) >= 0 ? (((X) + (1 << (SHIFT_AMOUNT - 1))) >> SHIFT_AMOUNT) \
            : (((X) - (1 << (SHIFT_AMOUNT - 1))) >> SHIFT_AMOUNT))
// Add x and y.
#define FLOAT_ADD(X, Y) ((X) + (Y))
// Subtract y from x.
#define FLOAT_SUB(X, Y) ((X) - (Y))
// Add x and n.
#define MIX_ADD(X, N) ((X)) + ((N) << SHIFT_AMOUNT)
// Subtract n from x.
#define MIX_SUB(X, N) ((X)) - ((N) << SHIFT_AMOUNT)
// Multiply x by y.
#define FLOAT_MUL(X, Y) ((fixed_t)(((int64_t)X) * Y >> SHIFT_AMOUNT))
// Multiply x by n.
#define MIX_MUL(X, N) ((X) * (N))
// Divide x by y.
#define FLOAT_DIV(X, Y) ((fixed_t)((((int64_t)X) << SHIFT_AMOUNT) / Y))
// Divide x by n.
#define MIX_DIV(X, N) ((X) / (N))

#endif
