/*
 * Parts of this file are copyright (c) 2019-2021 by Damiano Mazzella
 * The remainder is copyright (c) 2023 by the AUTHORS under the LICENSE
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */


#include "py/objint.h"
#include "py/parsenum.h"
#include "py/runtime.h"
#include "tfm/tfm_mpi.h"


#define MILLER_RABIN_ITERATIONS 40  // https://security.stackexchange.com/a/4546/287397
#define RADIX_10 10


// Make sure calls to malloc and free are mapped appropriately
#if defined(__thumb2__) || defined(__thumb__) || defined(__arm__)
#if !defined(malloc) || !defined(free)
void *malloc(size_t n) {
    void *ptr = m_malloc(n);
    return ptr;
}

void free(void *ptr) {
    m_free(ptr);
}
#endif
#endif

/**
Converts an integer (mp_obj_type) to an mpz_t.

Args:
    integer: The integer object to be converted.

    temp: A pointer to an instance of mpz_t where the converted value will be stored if the integer argument is a small
        integer object.

Returns:
    result (mpz_t *): A pointer to the mpz_t representation of the integer argument.
*/
STATIC mpz_t *mp_mpz_for_int(mp_obj_t integer, mpz_t *temp) {
    if (MP_OBJ_IS_SMALL_INT(integer)) {
        mpz_init_from_int(temp, MP_OBJ_SMALL_INT_VALUE(integer));
        return temp;
    } else {
        mp_obj_int_t *arp_p = MP_OBJ_TO_PTR(integer);
        return &(arp_p->mpz);
    }
}

/**
Converts an instance of mpz_t to a string representation in a specified base.

Args:
    i (mpz_t *): A pointer to the instance of mpz_t to be converted.

    radix (uint8_t): An integer representing the radix (base) in which the instance of mpz_t is to be represented.

Returns:
    result (char *): The initialized string.
*/
STATIC char *mpz_as_str(const mpz_t *i, uint8_t radix) {
    char *s = m_new(char, mp_int_format_size(mpz_max_num_bits(i), radix, NULL, '\0'));
    mpz_as_str_inpl(i, radix, NULL, 'a', '\0', s);
    return s;
}


/**
Converts an integer (mp_obj_type) to an fp_int.

Args:
    integer (mp_obj_type): The integer object to be converted.

    ft_tmp (fp_int *): A pointer to an fp_int type where the converted value will be stored.

    radix (uint8_t): An integer representing the radix (base) in which the integer object is represented.

Returns:
    result (bool): True upon success.
*/
STATIC bool mp_fp_for_int(mp_obj_t integer, fp_int *ft_tmp, uint8_t radix) {
    mpz_t arp_temp;
    fp_init(ft_tmp);
    mpz_t *arp_p = mp_mpz_for_int(integer, &arp_temp);
    char *s = mpz_as_str(arp_p, radix);
    fp_read_radix(ft_tmp, s, radix);
    if (arp_p == &arp_temp) {
        mpz_deinit(arp_p);
    }
    return true;
}


/**
Creates a new instance of string (vstr_t *) from an instance of fp_int.

Args:
    fp (const fp_int *): A pointer to an fp_int.

    radix (uint8_t): An integer representing the radix (base) in which the fp_int value is represented.

Returns:
    result (vstr_t *): The vstr_t pointer to a string representation of the fp_int.
*/
STATIC vstr_t *vstr_from_fp(const fp_int *fp, uint8_t radix) {
    int size_fp;
    fp_radix_size((fp_int *)fp, radix, &size_fp);
    vstr_t *vstr_fp = vstr_new(size_fp);
    vstr_fp->len = size_fp;
    fp_toradix_n((fp_int *)fp, vstr_fp->buf, radix, size_fp);
    return vstr_fp;
}

/**
Creates a new instance of integer (mp_obj_type) from an instance of fp_int.

Args:
    fp (const fp_int *): A pointer to an fp_int.

    radix (uint8_t): An integer representing the radix (base) in which the fp_int value is represented.

Returns:
    result (mp_obj_type): The mp_obj_type (integer) representation of the fp_int.
*/
STATIC mp_obj_t mp_obj_new_int_from_fp(const fp_int *fp, uint8_t radix) {
    vstr_t *vstr_out = vstr_from_fp((fp_int *)fp, radix);
    return mp_parse_num_integer(vstr_out->buf, vstr_out->len - 1, radix, NULL);
}


/**
Callback function for fp_prime_random_ex which uses a loop to iterate over the dst array and fill it with random integer
values using the FP_GEN_RANDOM() function. It then returns the length of the dst array.

Args:
    dst (unsigned char *): A pointer to an unsigned char array where the generated random integers will be stored.

    len (int): An integer representing the length of the dst array.

    dat (void *): A void pointer that can be used to pass data to the callback function. It is not used in this
        function, but is required because fp_prime_random_ex passes it in when callbacks are made.

Returns:
    result (int): The length of the dst array.
*/
STATIC int fp_prime_random_ex_cb(unsigned char *dst, int len, void *dat) {
    // Fill dst with random integer values
    for (int i = 0; i < len; i++) {
        dst[i] = FP_GEN_RANDOM();
    }

    return len;
}


/**
Count bits required to represent the absolute value of integer "i".  If the value of i is zero, zero is returned.

Args:
    integer_in (mp_obj_type): The integer "i".

Returns:
    result (mp_obj_type): The number of bits required to represent the absolute value of integer "i".
*/
STATIC mp_obj_t mod_count_bits(mp_obj_t integer_in) {
    // Init an fp_int to store the integer
    fp_int integer;
    mp_fp_for_int(integer_in, &integer, RADIX_10);

    // Count the bits required to represent integer
    int bit_cnt = fp_count_bits(&integer);

    return mp_obj_new_int(bit_cnt);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_count_bits_obj, mod_count_bits);


/**
Count bytes required to represent the absolute value of integer "i".  If the value of i is zero, one is returned.

Args:
    integer_in (mp_obj_type): The integer "i".

Returns:
    result (mp_obj_type): The number of bytes required to represent the absolute value of integer "i".
*/
STATIC mp_obj_t mod_count_bytes(mp_obj_t integer_in) {
    // Init an fp_int to store the integer
    fp_int integer;
    mp_fp_for_int(integer_in, &integer, RADIX_10);

    if(fp_iszero(&integer) == FP_YES) {
        return mp_obj_new_int(1);
    } else {
        // Init an fp_int to store the integer bit count
        fp_int integer_bit_cnt;
        fp_set(&integer_bit_cnt, fp_count_bits(&integer));

        // Init an fp_int to store the quotient
        fp_int quotient;
        fp_init(&quotient);

        // Init an fp_digit to store the remainder
        fp_digit remainder;

        // Count the bytes required to represent integer
        fp_div_d(&integer_bit_cnt, 8, &quotient, &remainder);
        if(remainder != 0) {
            fp_add_d(&quotient, 1, &quotient);
        }

        return mp_obj_new_int_from_fp(&quotient, RADIX_10);
    }
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_count_bytes_obj, mod_count_bytes);


/**
Get integer "i" raised to the power of exponent "e", modulo modulus "n".

Args:
    integer_in (mp_obj_type): The integer "i".

    exponent_in (mp_obj_type): The exponent "e".

    modulus_in (mp_obj_type): The modulus "n".

Returns:
    result (mp_obj_type): The modular exponentiation of integer "i" raised to the power of exponent "e", modulo modulus
        "n".

Raises:
    ValueError: If integer "i" is negative.

    ValueError: If modulus "n" is even.

    ValueError: If exponent "e" is even.

    ValueError: If integer "i" is greater than modulus "n".
*/
STATIC mp_obj_t mod_exptmod(mp_obj_t integer_in, mp_obj_t exponent_in, mp_obj_t modulus_in) {
    fp_int integer, exponent, modulus, result;
    mp_fp_for_int(integer_in, &integer, RADIX_10);
    mp_fp_for_int(exponent_in, &exponent, RADIX_10);
    mp_fp_for_int(modulus_in, &modulus, RADIX_10);
    fp_set(&result, 1);

    if(integer.sign == FP_NEG) {
        mp_raise_msg(&mp_type_ValueError, "Expected integer to have a non-negative value");
    }

    if (fp_iseven(&modulus) == FP_YES) {
        mp_raise_msg(&mp_type_ValueError, "Expected modulus to odd");
    }

    if (fp_iseven(&exponent) == FP_YES) {
        mp_raise_msg(&mp_type_ValueError, "Expected exponent to odd");
    }

    if(fp_cmp(&integer, &modulus) == FP_GT ) {
        mp_raise_msg(&mp_type_ValueError, "Expected modulus to be greater than integer");
    }

    fp_exptmod(&integer, &exponent, &modulus, &result);

    return mp_obj_new_int_from_fp(&result, RADIX_10);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_3(mod_exptmod_obj, mod_exptmod);


/**
Generate a prime number of the specified bit count.

Args:
    bit_cnt (mp_obj_t): An integer specifying the number of bits in the generated prime number. Default is 1024.

    miller_rabin_iterations (mp_obj_t): An integer specifying the number of iterations of the Miller-Rabin primality
        test to perform. Default value is equal to the value of MILLER_RABIN_ITERATIONS.

    safe_prime (mp_obj_t): A boolean indicating whether the generated prime number should be a "safe" prime, i.e. a
        prime number of the form p = 2 * q + 1, where q is also a prime. Default value is false.

Returns:
    result (mp_obj_t): A prime number of the specified bit count.

Raises:
    ValueError: If generated prime does not have the required number of bits.
*/
STATIC mp_obj_t mod_gen_prime(mp_uint_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    static const mp_arg_t allowed_args[] = {
        {MP_QSTR_bit_cnt, MP_ARG_INT, {.u_int = 1024}},
        {MP_QSTR_miller_rabin_iterations, MP_ARG_INT, {.u_int = MILLER_RABIN_ITERATIONS}},
        {MP_QSTR_safe_prime, MP_ARG_BOOL, {.u_bool = false}},
    };

    struct {
        mp_arg_val_t bit_cnt, miller_rabin_iterations, safe_prime;
    } args;

    mp_arg_parse_all(n_args, pos_args, kw_args, MP_ARRAY_SIZE(allowed_args), allowed_args, (mp_arg_val_t *)&args);

    if (args.bit_cnt.u_int < 16 || args.bit_cnt.u_int > 4096) {
        mp_raise_msg_varg(&mp_type_ValueError, MP_ERROR_TEXT("Expected number of bits to generate a prime number to be in the range  16 - 4096, but got %lu"), args.bit_cnt.u_int);
    }

    int flags = ((FP_GEN_RANDOM() & 1) ? TFM_PRIME_2MSB_OFF : TFM_PRIME_2MSB_ON);

    if (args.safe_prime.u_bool) {
        flags |= TFM_PRIME_SAFE;
    }

    fp_int a_fp_int;
    int result = fp_prime_random_ex(&a_fp_int, args.miller_rabin_iterations.u_int, args.bit_cnt.u_int, flags, fp_prime_random_ex_cb, NULL);
    if (result == FP_OKAY) {
        if (fp_count_bits(&a_fp_int) != args.bit_cnt.u_int) {
            mp_raise_msg_varg(&mp_type_ValueError, MP_ERROR_TEXT("Expected prime number to have %d bits, but got %lu"), fp_count_bits(&a_fp_int), args.bit_cnt.u_int);
        }
    } else {
        mp_raise_msg_varg(&mp_type_ValueError, MP_ERROR_TEXT("%d"), result);
    }

    return mp_obj_new_int_from_fp(&a_fp_int, RADIX_10);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_KW(mod_gen_prime_obj, 1, mod_gen_prime);


/**
Generates a random integer "r" for a given modulus "n", where 1 < r < n and gcd(r, n) == 1. The random integer "r" is
used for "blinding" during modular exponentiation.

Args:
    modulus_in (mp_obj_t): The modulus "n".

Returns:
    result (mp_obj_t): The randomly generated integer "r".

Raises:
    ValueError: If modulus "n" is even.
*/
STATIC mp_obj_t mod_gen_rand_int_for_blinding(mp_obj_t modulus_in) {
    // Init an fp_int to store the GCD
    fp_int gcd;
    fp_init(&gcd);

    // Init an fp_int to store the modulus
    fp_int modulus;
    mp_fp_for_int(modulus_in, &modulus, RADIX_10);

    // Init an fp_int to store the value of 1 (used in various fp functions)
    fp_int one;
    fp_set(&one, 1);

    // Init an fp_int to store the random integer
    fp_int rand_int;
    fp_init(&rand_int);

    // Verify modulus is odd
    if (fp_iseven(&modulus) == FP_YES) {
        mp_raise_msg(&mp_type_ValueError, "Expected modulus to odd");
    }

    // Get modulus bit count
    int modulus_bit_cnt = fp_count_bits(&modulus);

    do {
        do {
            // Generate the random integer
            fp_rand(&rand_int, modulus.used);

            // Count the random integer's bits
            int rand_int_bit_cnt = fp_count_bits(&rand_int);

            // If the random integer has more bits than the modulus, right shift the random integer's bits by a random
            // value that is at least the difference of the bit count between the random integer and the modulus, but
            // not more than the bit count of the random integer
            if(modulus_bit_cnt < rand_int_bit_cnt) {
                int shift_val = rand();
                while(1) {
                    // Get a random shift value
                    shift_val = rand();

                    // Make sure the shift value is not less than the minimum allowed size
                    if(shift_val < rand_int_bit_cnt - modulus_bit_cnt)  {
                        continue;
                    }

                    // Make sure the shift value is not greater than the maximum allowed size
                    shift_val %= rand_int_bit_cnt;

                    break;
                }

                // Shift the random integer right by the shift value
                fp_div_2d(&rand_int, shift_val, &rand_int, NULL);
            }

        // Verify the random integer meets criteria 1 < r < n
        } while(fp_cmp(&one, &rand_int) != FP_LT || fp_cmp(&rand_int, &modulus) != FP_LT);

        // Get the GDC of the random integer and modulus
        fp_gcd(&modulus, &rand_int, &gcd);

    // Verify the random integer meets criteria gdc(r, n) == 1
    } while(fp_cmp(&gcd, &one) != FP_EQ);

    return mp_obj_new_int_from_fp(&rand_int, RADIX_10);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_gen_rand_int_for_blinding_obj, mod_gen_rand_int_for_blinding);


/**
Get the modular inverse of integer "i" modulo an modulus "n".

Args:
    integer_in (mp_obj_t): The integer "i",

    modulus_in (mp_obj_t): The modulus "n".

Returns:
    result (mp_obj_t): The modular inverse of integer "i" modulo an modulus "n".

Raises:
    ValueError: If an inverse modulus cannot be found for i % n.
*/
STATIC mp_obj_t mod_invmod(mp_obj_t integer_in, mp_obj_t modulus_in) {
    // Init an fp_int to store the integer
    fp_int integer;
    mp_fp_for_int(integer_in, &integer, RADIX_10);

    // Init an fp_int to store the modulus
    fp_int modulus;
    mp_fp_for_int(modulus_in, &modulus, RADIX_10);

    // Init an fp_int to store the result
    fp_int result;
    fp_init(&result);

    // Perform modular inverse operation
    if(fp_invmod(&integer, &modulus, &result) != FP_OKAY) {
        mp_raise_msg(&mp_type_ValueError, "Modular inverse does not exist for supplied values");
    }

    return mp_obj_new_int_from_fp(&result, RADIX_10);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(mod_invmod_obj, mod_invmod);


/* Map function objects to the names that will be used to access them in Python files */
STATIC const mp_rom_map_elem_t mp_module_mprsa_globals_table[] = {
    {MP_OBJ_NEW_QSTR(MP_QSTR___name__), MP_OBJ_NEW_QSTR(MP_QSTR__mprsa)},
    {MP_ROM_QSTR(MP_QSTR_count_bits), MP_ROM_PTR(&mod_count_bits_obj)},
    {MP_ROM_QSTR(MP_QSTR_count_bytes), MP_ROM_PTR(&mod_count_bytes_obj)},
    {MP_ROM_QSTR(MP_QSTR_exptmod), MP_ROM_PTR(&mod_exptmod_obj)},
    {MP_ROM_QSTR(MP_QSTR_gen_prime), MP_ROM_PTR(&mod_gen_prime_obj)},
    {MP_ROM_QSTR(MP_QSTR_gen_rand_int_for_blinding), MP_ROM_PTR(&mod_gen_rand_int_for_blinding_obj)},
    {MP_ROM_QSTR(MP_QSTR_invmod), MP_ROM_PTR(&mod_invmod_obj)},
};
STATIC MP_DEFINE_CONST_DICT(mp_module_mprsa_globals, mp_module_mprsa_globals_table);

/* Define the mprsa module */
const mp_obj_module_t mp_module_mprsa = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&mp_module_mprsa_globals,
};

// Register the mprsa module to make it available in Python files
MP_REGISTER_MODULE(MP_QSTR__mprsa, mp_module_mprsa);
