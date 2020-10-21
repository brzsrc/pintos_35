#ifndef FIXED_POINT_H
#define FIXED_POINT_H

#define FRACTION 1 << 14
#define FLOAT(n) (n) * FRACTION
#define ROUND_ZERO(x) ((x) / FRACTION)
#define ROUND_NEAR(x) ((x) >= 0 ? ((x) + FRACTION / 2) / (FRACTION) : ((x)-FRACTION / 2) / (FRACTION))
#define FLOAT_ADD(x, y) ((x) + (y))
#define FLOAT_SUB(x, y) ((x) - (y))
#define INT_ADD(x, n) ((x))+(n)*FRACTION)
#define INT_SUB(x, n) ((x))-(n)*FRACTION)
#define FLOAT_MUL(x, y) ((int64_t)(x) * (y) / FRACTION)
#define INT_MUL(x, n) ((x) * (n))
#define FLOAT_DIV(x, y) ((int64_t)(x) * FRACTION / (y))
#define INT_DIV(x, n) ((x) / (n))

#endif