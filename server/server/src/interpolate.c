#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>

#include "memory.h"
#include "mpi.h"
#include "adhoc.h"


/* Basically we only need to raise Yi' to the power of lvi to get cert'
 * cert' = Y1'^lv1 * Y2'^lv2 * .. Yn'^lvn  mod N
 * however we might get fraction number of lvn
 * so we calculate lvn = dividen-n/divisor, note all lv has the same divisor
 * if we say :
 *       cert' ^ divisor = Y1'^dividen1 * Y2'^dividen2 * .... YN^dividenN = w
 * for RSA  : HASH (message) = cert' ^ e mod N
 * then     : HASH (message) ^ divisor = w^e = cert'^(divisor*e)
 * we need to find cert' = w^a*x^b
 * because gcd (e,divisor) = 1 we can use extended euclidian function to find
 * a and b such as : divisor*a + e*b = 1 */

void
sort (uint32_t * x, MPI * y, unsigned num)
{
  int i = 0;
  int j = 0;
  uint32_t temp;
  MPI tempMPI;

  for (i = 1; i < num; i++)
    {
      j = i;
      while ((j != 0) && (x[j] < x[j - 1]))
        {
          temp = x[j];
          x[j] = x[j - 1];
          x[j - 1] = temp;

          if (y)
            {
              tempMPI = y[j];
              y[j] = y[j - 1];
              y[j - 1] = tempMPI;
            }

          j--;
        }
    }
  return;
}

MPI
calculate_divisor (uint32_t * x, unsigned num)
{
  int i, j;
  MPI res = mpi_alloc (0);

  mpi_set_ui (res, 1);
  /* divisor = (xn -x0) * (xn - x1) * .... (x1 - x0) */
  for (i = 0; i < num; i++)
    for (j = (i + 1); j < num; j++)
      {
        /* mpi can only multiply with positif number, 
         * because it use unsigned integer, so we must
         * take care of the sign */
        if (x[j] > x[i])
          mpi_mul_ui (res, res, (x[j] - x[i]));
        else
          {
            mpi_mul_ui (res, res, (x[i] - x[j]));
            res->sign ^= 1;
          }
      }

  return res;
}

ext_euclidean (MPI * resd, MPI * resx, MPI * resy, MPI e, MPI e1)
{
  MPI g = mpi_alloc_set_ui (1);
  MPI x = mpi_copy (e);
  MPI y = mpi_copy (e1);
  MPI u = mpi_alloc (0);
  MPI v = mpi_alloc (0);
  MPI A = mpi_alloc_set_ui (1);
  MPI B = mpi_alloc_set_ui (0);
  MPI C = mpi_alloc_set_ui (0);
  MPI D = mpi_alloc_set_ui (1);


  while (mpi_divisible_ui (x, 2) && mpi_divisible_ui (y, 2))
    {
      mpi_rshift (x, x, 1);
      mpi_rshift (y, y, 1);
      mpi_mul_ui (g, g, 2);
    }

  mpi_set (u, x);
  mpi_set (v, y);


  do
    {

      while (mpi_divisible_ui (u, 2))
        {
          mpi_rshift (u, u, 1);
          if (mpi_divisible_ui (A, 2) && mpi_divisible_ui (B, 2))
            {
              mpi_rshift (A, A, 1);
              mpi_rshift (B, B, 1);
            }
          else
            {
              mpi_add (A, A, y);
              mpi_rshift (A, A, 1);
              mpi_sub (B, B, x);
              mpi_rshift (B, B, 1);
            }
        }

      while (mpi_divisible_ui (v, 2))
        {
          mpi_rshift (v, v, 1);
          if (mpi_divisible_ui (C, 2) && mpi_divisible_ui (D, 2))
            {
              mpi_rshift (C, C, 1);
              mpi_rshift (D, D, 1);
            }
          else
            {
              mpi_add (C, C, y);
              mpi_rshift (C, C, 1);
              mpi_sub (D, D, x);
              mpi_rshift (D, D, 1);
            }
        }

      if (mpi_cmp (u, v) != -1)
        {
          mpi_sub (u, u, v);
          mpi_sub (A, A, C);
          mpi_sub (B, B, D);
        }
      else
        {
          mpi_sub (v, v, u);
          mpi_sub (C, C, A);
          mpi_sub (D, D, B);
        }

    }
  while (mpi_cmp_ui (u, 0) != 0);

  mpi_mul (g, g, v);
  *resd = g;
  *resx = C;
  *resy = D;


  mpi_free (u);
  mpi_free (v);
  mpi_free (x);
  mpi_free (y);
  mpi_free (A);
  mpi_free (B);
}



/* Get positive exponential from negative one
 * when calculated over Zn. return 0 on success
 * or 1 when fail
 */
int
get_positive (MPI * base, MPI * exp, MPI N)
{
  MPI d = NULL;
  MPI x = NULL;
  MPI y = NULL;
  MPI e = mpi_copy (*exp);
  MPI b = mpi_copy (*base);
  int rc = 0;

  if (e->sign == 0)
    {
      rc = 0;
      mpi_free (e);
      mpi_free (b);
      return rc;
    }

  /* calculate extended euclidean function,
   * if gcd(a,N) = 1 then we can find a^-1 mod N.
   * Next step will be replacing a with x and change
   * exponential to positive.
   */
  ext_euclidean (&d, &x, &y, b, N);
  if (mpi_cmp_ui (d, 1) == 1)
    {
      /* d is bigger then 1 */
      rc = 1;
      goto leave;
    }
  /* We have the result of a^-1 mod N on x
   */
  mpi_free (*base);
  *base = x;
  e->sign = 0;
  mpi_free (*exp);
  *exp = e;
  rc = 0;

leave:
  mpi_free (d);
  mpi_free (y);
  mpi_free (b);
  return rc;
}


calculate_dividen (MPI * dividen, uint32_t * x, int num)
{
  int i, j, k;

  /* example v1 = (v2*v3*..vn)*(vn - v2)(vn - v3)....(v3 -v2) */
  for (i = 0; i < num; i++)
    {
      dividen[i] = mpi_alloc (0);
      mpi_set_ui (dividen[i], 1);
      if (i % 2)
        dividen[i]->sign = 1;
      else
        dividen[i]->sign = 0;

      for (j = 0; j < num; j++)
        {
          if (i != j)
            {
              /* this is for the first part of the equation above */
              mpi_mul_ui (dividen[i], dividen[i], x[j]);
              for (k = num - 1; k > j; k--)
                {
                  /* this if for the rest of the equation */
                  if (i != k)
                    {
                      if (x[k] > x[j])
                        mpi_mul_ui (dividen[i], dividen[i], (x[k] - x[j]));
                      else
                        {
                          mpi_mul_ui (dividen[i], dividen[i], (x[j] - x[k]));
                          dividen[i]->sign ^= 1;
                        }
                    }
                }
            }
        }
    }
}

MPI
final (MPI * base, MPI * dividen, MPI N, unsigned num)
{
  int i;
  MPI res = mpi_alloc (0);

  /* first set all power to positive */
  for (i = 0; i < num; i++)
    {
      if (dividen[i]->sign)
        if (get_positive (&base[i], &dividen[i], N))
          {
            /* we can not converted it into positive,
             * then we can not calculate the rest 
             */
            mpi_free (res);
            return NULL;
          }
    }
  mpi_mulpowm (res, base, dividen, N);

  return res;
}

int
compare (MPI w, MPI x, MPI divisor, PKT_public_key * pk)
{
  MPI WpowE = mpi_alloc (0);
  MPI XpowDiv = mpi_alloc (0);
  int rc;

  /* w^e mod N */
  mpi_powm (WpowE, w, pk->pkey[1], pk->pkey[0]);

  /* x^divisor mod N */
  mpi_powm (XpowDiv, x, divisor, pk->pkey[0]);

  rc = mpi_cmp (WpowE, XpowDiv);
  return rc;
}



MPI
get_certificate (MPI w, MPI hash, MPI e, MPI e1, MPI N)
{
  MPI x = NULL;
  MPI y = NULL;
  MPI d = NULL;
  MPI res = NULL;
  MPI res1 = mpi_alloc (0);
  MPI res2 = mpi_alloc (0);
  MPI tmpH = mpi_copy (hash);
  MPI tmpW = mpi_copy (w);
  int verbose = 0;

  /* First find euclidean x and y */
  ext_euclidean (&d, &x, &y, e1, e);


  /* result = w^x * hash^y mod N */

  if (x->sign)
    if (get_positive (&tmpW, &x, N))
      /* We can not convert to positive exp */
      goto leave;
  mpi_powm (res1, tmpW, x, N);

  if (y->sign)
    {
      if (get_positive (&tmpH, &y, N))
        /* We can not convert to positive exp */
        goto leave;
    }
  mpi_powm (res2, tmpH, y, N);

  res = mpi_alloc (0);
  mpi_mulm (res, res1, res2, N);


leave:
  mpi_free (x);
  mpi_free (y);
  mpi_free (d);
  mpi_free (tmpH);
  mpi_free (tmpW);
  mpi_free (res1);
  mpi_free (res2);
  return res;
}



MPI
interpolate (MPI * y, PKT_public_key * pk, MPI hash, uint32_t * x,
             unsigned num)
{
  MPI divisor = mpi_alloc (0);
  MPI dividen[MAXSPLIT] = { NULL };
  int i;
  MPI res = NULL;
  MPI w = NULL;


  /* we need to sort partial signature in ascending order based on
   * id, so we will not have a negative number in divisor calculation
   * because we always do (Xa - Xb) where a > b in calculating
   * divisor and dividend
   */

  sort (x, y, num);

  divisor = calculate_divisor (x, num);
  calculate_dividen (dividen, x, num);


  /* we got w below */
  w = final (y, dividen, pk->pkey[0], num);
  if (!w)
    goto leave;


  /* compare it with our hash */
  if (compare (w, hash, divisor, pk))
    {
      log_error ("fail to compare\n");
      goto leave;
    }

  res = get_certificate (w, hash, pk->pkey[1], divisor, pk->pkey[0]);
  if (res)
    mpi_free (w);
  else
    res = NULL;

leave:
  /* free dividend and divisor */
  for (i = 0; i < num; i++)
    mpi_free (dividen[i]);
  mpi_free (divisor);

  return res;
}

MPI
calculate_dividen1 (uint32_t xi, uint32_t * x, int pos, int num)
{
  int j, k;
  MPI dividen = mpi_alloc_set_ui (1);


  if (pos % 2)
    dividen->sign = 1;
  else
    dividen->sign = 0;
  /* example v1 = ((vi - v2)*(vi - v3)*..(vi - vn))*(v2 - v3)(v2 - v4)....(vn-1 -vn) */
  for (j = 0; j < num; j++)
    {
      if (pos != j)
        {
          /* this is for the first part of the equation above */
          if (xi > x[j])
            mpi_mul_ui (dividen, dividen, xi - x[j]);
          else
            {
              mpi_mul_ui (dividen, dividen, x[j] - xi);
              dividen->sign ^= 1;
            }
          for (k = j + 1; k < num; k++)
            {
              /* this if for the rest of the equation */
              if (pos != k)
                {
                  if (x[j] > x[k])
                    mpi_mul_ui (dividen, dividen, (x[j] - x[k]));
                  else
                    {
                      mpi_mul_ui (dividen, dividen, (x[k] - x[j]));
                      dividen->sign ^= 1;
                    }
                }
            }
        }
    }
  return dividen;
}

MPI
calculate_divisor1 (uint32_t * x, unsigned num)
{
  int i, j;
  MPI res = mpi_alloc (0);

  mpi_set_ui (res, 1);
  /* divisor = (x1 -x2) * (x1 - x3) * .... (xn-1 - xn) */
  for (i = 0; i < num; i++)
    for (j = (i + 1); j < num; j++)
      {
        /* mpi can only multiply with positif number, 
         * because it use unsigned integer, so we must
         * take care of the sign */
        if (x[i] > x[j])
          mpi_mul_ui (res, res, (x[i] - x[j]));
        else
          {
            mpi_mul_ui (res, res, (x[j] - x[i]));
            res->sign ^= 1;
          }
      }

  return res;
}
