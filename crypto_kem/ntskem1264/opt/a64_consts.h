/**
 *  a64_consts.h
 *  NTS-KEM
 *
 *  Parameter: NTS-KEM(12, 64)
 *  Platform: Intel 64-bit
 *
 *  This file is part of the optimized implemention of NTS-KEM
 *  submitted as part of NIST Post-Quantum Cryptography
 *  Standardization Process.
 **/

#include <stdint.h>

#ifndef __A64_CONSTS_H
#define __A64_CONSTS_H

uint64_t a64_consts_64[][12] =
{
    {
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFF0000FFFF0000ULL,
        0x0000000000000000ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x0000000000000000ULL,
        0x55AA55AA55AA55AAULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000000000000000ULL,
        0xFF00FF00FF00FF00ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x3333CCCC3333CCCCULL,
        0xAAAAAAAAAAAAAAAAULL,
    },
    {
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFF0000FFFF0000ULL,
        0x0000000000000000ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x0000000000000000ULL,
        0xAA55AA55AA55AA55ULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000000000000000ULL,
        0xFF00FF00FF00FF00ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x3333CCCC3333CCCCULL,
        0xAAAAAAAAAAAAAAAAULL,
    },
    {
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000FFFF0000FFFFULL,
        0x0000000000000000ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x55AA55AA55AA55AAULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xFF00FF00FF00FF00ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x3333CCCC3333CCCCULL,
        0xAAAAAAAAAAAAAAAAULL,
    },
    {
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000FFFF0000FFFFULL,
        0x0000000000000000ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xAA55AA55AA55AA55ULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xFF00FF00FF00FF00ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x3333CCCC3333CCCCULL,
        0xAAAAAAAAAAAAAAAAULL,
    },
    {
        0xF0F0F0F00F0F0F0FULL,
        0xFFFF0000FFFF0000ULL,
        0x0000000000000000ULL,
        0x0F0F0F0F0F0F0F0FULL,
        0x0000000000000000ULL,
        0x55AA55AA55AA55AAULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000000000000000ULL,
        0xFF00FF00FF00FF00ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x3333CCCC3333CCCCULL,
        0xAAAAAAAAAAAAAAAAULL,
    },
    {
        0xF0F0F0F00F0F0F0FULL,
        0xFFFF0000FFFF0000ULL,
        0x0000000000000000ULL,
        0x0F0F0F0F0F0F0F0FULL,
        0x0000000000000000ULL,
        0xAA55AA55AA55AA55ULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000000000000000ULL,
        0xFF00FF00FF00FF00ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x3333CCCC3333CCCCULL,
        0xAAAAAAAAAAAAAAAAULL,
    },
    {
        0xF0F0F0F00F0F0F0FULL,
        0x0000FFFF0000FFFFULL,
        0x0000000000000000ULL,
        0x0F0F0F0F0F0F0F0FULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x55AA55AA55AA55AAULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xFF00FF00FF00FF00ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x3333CCCC3333CCCCULL,
        0xAAAAAAAAAAAAAAAAULL,
    },
    {
        0xF0F0F0F00F0F0F0FULL,
        0x0000FFFF0000FFFFULL,
        0x0000000000000000ULL,
        0x0F0F0F0F0F0F0F0FULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xAA55AA55AA55AA55ULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xFF00FF00FF00FF00ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x3333CCCC3333CCCCULL,
        0xAAAAAAAAAAAAAAAAULL,
    },
    {
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFF0000FFFF0000ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x0000000000000000ULL,
        0xAA55AA55AA55AA55ULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000000000000000ULL,
        0x00FF00FF00FF00FFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x3333CCCC3333CCCCULL,
        0x5555555555555555ULL,
    },
    {
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFF0000FFFF0000ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x0000000000000000ULL,
        0x55AA55AA55AA55AAULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000000000000000ULL,
        0x00FF00FF00FF00FFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x3333CCCC3333CCCCULL,
        0x5555555555555555ULL,
    },
    {
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000FFFF0000FFFFULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xAA55AA55AA55AA55ULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x00FF00FF00FF00FFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x3333CCCC3333CCCCULL,
        0x5555555555555555ULL,
    },
    {
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000FFFF0000FFFFULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x55AA55AA55AA55AAULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x00FF00FF00FF00FFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x3333CCCC3333CCCCULL,
        0x5555555555555555ULL,
    },
    {
        0xF0F0F0F00F0F0F0FULL,
        0xFFFF0000FFFF0000ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x0F0F0F0F0F0F0F0FULL,
        0x0000000000000000ULL,
        0xAA55AA55AA55AA55ULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000000000000000ULL,
        0x00FF00FF00FF00FFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x3333CCCC3333CCCCULL,
        0x5555555555555555ULL,
    },
    {
        0xF0F0F0F00F0F0F0FULL,
        0xFFFF0000FFFF0000ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x0F0F0F0F0F0F0F0FULL,
        0x0000000000000000ULL,
        0x55AA55AA55AA55AAULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000000000000000ULL,
        0x00FF00FF00FF00FFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x3333CCCC3333CCCCULL,
        0x5555555555555555ULL,
    },
    {
        0xF0F0F0F00F0F0F0FULL,
        0x0000FFFF0000FFFFULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x0F0F0F0F0F0F0F0FULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xAA55AA55AA55AA55ULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x00FF00FF00FF00FFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x3333CCCC3333CCCCULL,
        0x5555555555555555ULL,
    },
    {
        0xF0F0F0F00F0F0F0FULL,
        0x0000FFFF0000FFFFULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x0F0F0F0F0F0F0F0FULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x55AA55AA55AA55AAULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x00FF00FF00FF00FFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x3333CCCC3333CCCCULL,
        0x5555555555555555ULL,
    },
    {
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFF0000FFFF0000ULL,
        0x0000000000000000ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x0000000000000000ULL,
        0x55AA55AA55AA55AAULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xFF00FF00FF00FF00ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xCCCC3333CCCC3333ULL,
        0xAAAAAAAAAAAAAAAAULL,
    },
    {
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFF0000FFFF0000ULL,
        0x0000000000000000ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x0000000000000000ULL,
        0xAA55AA55AA55AA55ULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xFF00FF00FF00FF00ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xCCCC3333CCCC3333ULL,
        0xAAAAAAAAAAAAAAAAULL,
    },
    {
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000FFFF0000FFFFULL,
        0x0000000000000000ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x55AA55AA55AA55AAULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000000000000000ULL,
        0xFF00FF00FF00FF00ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xCCCC3333CCCC3333ULL,
        0xAAAAAAAAAAAAAAAAULL,
    },
    {
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000FFFF0000FFFFULL,
        0x0000000000000000ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xAA55AA55AA55AA55ULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000000000000000ULL,
        0xFF00FF00FF00FF00ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xCCCC3333CCCC3333ULL,
        0xAAAAAAAAAAAAAAAAULL,
    },
    {
        0xF0F0F0F00F0F0F0FULL,
        0xFFFF0000FFFF0000ULL,
        0x0000000000000000ULL,
        0x0F0F0F0F0F0F0F0FULL,
        0x0000000000000000ULL,
        0x55AA55AA55AA55AAULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xFF00FF00FF00FF00ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xCCCC3333CCCC3333ULL,
        0xAAAAAAAAAAAAAAAAULL,
    },
    {
        0xF0F0F0F00F0F0F0FULL,
        0xFFFF0000FFFF0000ULL,
        0x0000000000000000ULL,
        0x0F0F0F0F0F0F0F0FULL,
        0x0000000000000000ULL,
        0xAA55AA55AA55AA55ULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xFF00FF00FF00FF00ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xCCCC3333CCCC3333ULL,
        0xAAAAAAAAAAAAAAAAULL,
    },
    {
        0xF0F0F0F00F0F0F0FULL,
        0x0000FFFF0000FFFFULL,
        0x0000000000000000ULL,
        0x0F0F0F0F0F0F0F0FULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x55AA55AA55AA55AAULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000000000000000ULL,
        0xFF00FF00FF00FF00ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xCCCC3333CCCC3333ULL,
        0xAAAAAAAAAAAAAAAAULL,
    },
    {
        0xF0F0F0F00F0F0F0FULL,
        0x0000FFFF0000FFFFULL,
        0x0000000000000000ULL,
        0x0F0F0F0F0F0F0F0FULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xAA55AA55AA55AA55ULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000000000000000ULL,
        0xFF00FF00FF00FF00ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xCCCC3333CCCC3333ULL,
        0xAAAAAAAAAAAAAAAAULL,
    },
    {
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFF0000FFFF0000ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x0000000000000000ULL,
        0xAA55AA55AA55AA55ULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x00FF00FF00FF00FFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xCCCC3333CCCC3333ULL,
        0x5555555555555555ULL,
    },
    {
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFF0000FFFF0000ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x0000000000000000ULL,
        0x55AA55AA55AA55AAULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x00FF00FF00FF00FFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xCCCC3333CCCC3333ULL,
        0x5555555555555555ULL,
    },
    {
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000FFFF0000FFFFULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xAA55AA55AA55AA55ULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000000000000000ULL,
        0x00FF00FF00FF00FFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xCCCC3333CCCC3333ULL,
        0x5555555555555555ULL,
    },
    {
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000FFFF0000FFFFULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x55AA55AA55AA55AAULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000000000000000ULL,
        0x00FF00FF00FF00FFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xCCCC3333CCCC3333ULL,
        0x5555555555555555ULL,
    },
    {
        0xF0F0F0F00F0F0F0FULL,
        0xFFFF0000FFFF0000ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x0F0F0F0F0F0F0F0FULL,
        0x0000000000000000ULL,
        0xAA55AA55AA55AA55ULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x00FF00FF00FF00FFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xCCCC3333CCCC3333ULL,
        0x5555555555555555ULL,
    },
    {
        0xF0F0F0F00F0F0F0FULL,
        0xFFFF0000FFFF0000ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x0F0F0F0F0F0F0F0FULL,
        0x0000000000000000ULL,
        0x55AA55AA55AA55AAULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x00FF00FF00FF00FFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xCCCC3333CCCC3333ULL,
        0x5555555555555555ULL,
    },
    {
        0xF0F0F0F00F0F0F0FULL,
        0x0000FFFF0000FFFFULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x0F0F0F0F0F0F0F0FULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xAA55AA55AA55AA55ULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000000000000000ULL,
        0x00FF00FF00FF00FFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xCCCC3333CCCC3333ULL,
        0x5555555555555555ULL,
    },
    {
        0xF0F0F0F00F0F0F0FULL,
        0x0000FFFF0000FFFFULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x0F0F0F0F0F0F0F0FULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x55AA55AA55AA55AAULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000000000000000ULL,
        0x00FF00FF00FF00FFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xCCCC3333CCCC3333ULL,
        0x5555555555555555ULL,
    },
    {
        0xF0F0F0F00F0F0F0FULL,
        0xFFFF0000FFFF0000ULL,
        0x0000000000000000ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x0000000000000000ULL,
        0x55AA55AA55AA55AAULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000000000000000ULL,
        0xFF00FF00FF00FF00ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x3333CCCC3333CCCCULL,
        0xAAAAAAAAAAAAAAAAULL,
    },
    {
        0xF0F0F0F00F0F0F0FULL,
        0xFFFF0000FFFF0000ULL,
        0x0000000000000000ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x0000000000000000ULL,
        0xAA55AA55AA55AA55ULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000000000000000ULL,
        0xFF00FF00FF00FF00ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x3333CCCC3333CCCCULL,
        0xAAAAAAAAAAAAAAAAULL,
    },
    {
        0xF0F0F0F00F0F0F0FULL,
        0x0000FFFF0000FFFFULL,
        0x0000000000000000ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x55AA55AA55AA55AAULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xFF00FF00FF00FF00ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x3333CCCC3333CCCCULL,
        0xAAAAAAAAAAAAAAAAULL,
    },
    {
        0xF0F0F0F00F0F0F0FULL,
        0x0000FFFF0000FFFFULL,
        0x0000000000000000ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xAA55AA55AA55AA55ULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xFF00FF00FF00FF00ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x3333CCCC3333CCCCULL,
        0xAAAAAAAAAAAAAAAAULL,
    },
    {
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFF0000FFFF0000ULL,
        0x0000000000000000ULL,
        0x0F0F0F0F0F0F0F0FULL,
        0x0000000000000000ULL,
        0x55AA55AA55AA55AAULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000000000000000ULL,
        0xFF00FF00FF00FF00ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x3333CCCC3333CCCCULL,
        0xAAAAAAAAAAAAAAAAULL,
    },
    {
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFF0000FFFF0000ULL,
        0x0000000000000000ULL,
        0x0F0F0F0F0F0F0F0FULL,
        0x0000000000000000ULL,
        0xAA55AA55AA55AA55ULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000000000000000ULL,
        0xFF00FF00FF00FF00ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x3333CCCC3333CCCCULL,
        0xAAAAAAAAAAAAAAAAULL,
    },
    {
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000FFFF0000FFFFULL,
        0x0000000000000000ULL,
        0x0F0F0F0F0F0F0F0FULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x55AA55AA55AA55AAULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xFF00FF00FF00FF00ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x3333CCCC3333CCCCULL,
        0xAAAAAAAAAAAAAAAAULL,
    },
    {
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000FFFF0000FFFFULL,
        0x0000000000000000ULL,
        0x0F0F0F0F0F0F0F0FULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xAA55AA55AA55AA55ULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xFF00FF00FF00FF00ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x3333CCCC3333CCCCULL,
        0xAAAAAAAAAAAAAAAAULL,
    },
    {
        0xF0F0F0F00F0F0F0FULL,
        0xFFFF0000FFFF0000ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x0000000000000000ULL,
        0xAA55AA55AA55AA55ULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000000000000000ULL,
        0x00FF00FF00FF00FFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x3333CCCC3333CCCCULL,
        0x5555555555555555ULL,
    },
    {
        0xF0F0F0F00F0F0F0FULL,
        0xFFFF0000FFFF0000ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x0000000000000000ULL,
        0x55AA55AA55AA55AAULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000000000000000ULL,
        0x00FF00FF00FF00FFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x3333CCCC3333CCCCULL,
        0x5555555555555555ULL,
    },
    {
        0xF0F0F0F00F0F0F0FULL,
        0x0000FFFF0000FFFFULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xAA55AA55AA55AA55ULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x00FF00FF00FF00FFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x3333CCCC3333CCCCULL,
        0x5555555555555555ULL,
    },
    {
        0xF0F0F0F00F0F0F0FULL,
        0x0000FFFF0000FFFFULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x55AA55AA55AA55AAULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x00FF00FF00FF00FFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x3333CCCC3333CCCCULL,
        0x5555555555555555ULL,
    },
    {
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFF0000FFFF0000ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x0F0F0F0F0F0F0F0FULL,
        0x0000000000000000ULL,
        0xAA55AA55AA55AA55ULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000000000000000ULL,
        0x00FF00FF00FF00FFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x3333CCCC3333CCCCULL,
        0x5555555555555555ULL,
    },
    {
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFF0000FFFF0000ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x0F0F0F0F0F0F0F0FULL,
        0x0000000000000000ULL,
        0x55AA55AA55AA55AAULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000000000000000ULL,
        0x00FF00FF00FF00FFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x3333CCCC3333CCCCULL,
        0x5555555555555555ULL,
    },
    {
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000FFFF0000FFFFULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x0F0F0F0F0F0F0F0FULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xAA55AA55AA55AA55ULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x00FF00FF00FF00FFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x3333CCCC3333CCCCULL,
        0x5555555555555555ULL,
    },
    {
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000FFFF0000FFFFULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x0F0F0F0F0F0F0F0FULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x55AA55AA55AA55AAULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x00FF00FF00FF00FFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x3333CCCC3333CCCCULL,
        0x5555555555555555ULL,
    },
    {
        0xF0F0F0F00F0F0F0FULL,
        0xFFFF0000FFFF0000ULL,
        0x0000000000000000ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x0000000000000000ULL,
        0x55AA55AA55AA55AAULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xFF00FF00FF00FF00ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xCCCC3333CCCC3333ULL,
        0xAAAAAAAAAAAAAAAAULL,
    },
    {
        0xF0F0F0F00F0F0F0FULL,
        0xFFFF0000FFFF0000ULL,
        0x0000000000000000ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x0000000000000000ULL,
        0xAA55AA55AA55AA55ULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xFF00FF00FF00FF00ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xCCCC3333CCCC3333ULL,
        0xAAAAAAAAAAAAAAAAULL,
    },
    {
        0xF0F0F0F00F0F0F0FULL,
        0x0000FFFF0000FFFFULL,
        0x0000000000000000ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x55AA55AA55AA55AAULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000000000000000ULL,
        0xFF00FF00FF00FF00ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xCCCC3333CCCC3333ULL,
        0xAAAAAAAAAAAAAAAAULL,
    },
    {
        0xF0F0F0F00F0F0F0FULL,
        0x0000FFFF0000FFFFULL,
        0x0000000000000000ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xAA55AA55AA55AA55ULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000000000000000ULL,
        0xFF00FF00FF00FF00ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xCCCC3333CCCC3333ULL,
        0xAAAAAAAAAAAAAAAAULL,
    },
    {
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFF0000FFFF0000ULL,
        0x0000000000000000ULL,
        0x0F0F0F0F0F0F0F0FULL,
        0x0000000000000000ULL,
        0x55AA55AA55AA55AAULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xFF00FF00FF00FF00ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xCCCC3333CCCC3333ULL,
        0xAAAAAAAAAAAAAAAAULL,
    },
    {
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFF0000FFFF0000ULL,
        0x0000000000000000ULL,
        0x0F0F0F0F0F0F0F0FULL,
        0x0000000000000000ULL,
        0xAA55AA55AA55AA55ULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xFF00FF00FF00FF00ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xCCCC3333CCCC3333ULL,
        0xAAAAAAAAAAAAAAAAULL,
    },
    {
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000FFFF0000FFFFULL,
        0x0000000000000000ULL,
        0x0F0F0F0F0F0F0F0FULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x55AA55AA55AA55AAULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000000000000000ULL,
        0xFF00FF00FF00FF00ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xCCCC3333CCCC3333ULL,
        0xAAAAAAAAAAAAAAAAULL,
    },
    {
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000FFFF0000FFFFULL,
        0x0000000000000000ULL,
        0x0F0F0F0F0F0F0F0FULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xAA55AA55AA55AA55ULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000000000000000ULL,
        0xFF00FF00FF00FF00ULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xCCCC3333CCCC3333ULL,
        0xAAAAAAAAAAAAAAAAULL,
    },
    {
        0xF0F0F0F00F0F0F0FULL,
        0xFFFF0000FFFF0000ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x0000000000000000ULL,
        0xAA55AA55AA55AA55ULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x00FF00FF00FF00FFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xCCCC3333CCCC3333ULL,
        0x5555555555555555ULL,
    },
    {
        0xF0F0F0F00F0F0F0FULL,
        0xFFFF0000FFFF0000ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0x0000000000000000ULL,
        0x55AA55AA55AA55AAULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x00FF00FF00FF00FFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xCCCC3333CCCC3333ULL,
        0x5555555555555555ULL,
    },
    {
        0xF0F0F0F00F0F0F0FULL,
        0x0000FFFF0000FFFFULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xAA55AA55AA55AA55ULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000000000000000ULL,
        0x00FF00FF00FF00FFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xCCCC3333CCCC3333ULL,
        0x5555555555555555ULL,
    },
    {
        0xF0F0F0F00F0F0F0FULL,
        0x0000FFFF0000FFFFULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x55AA55AA55AA55AAULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000000000000000ULL,
        0x00FF00FF00FF00FFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xCCCC3333CCCC3333ULL,
        0x5555555555555555ULL,
    },
    {
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFF0000FFFF0000ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x0F0F0F0F0F0F0F0FULL,
        0x0000000000000000ULL,
        0xAA55AA55AA55AA55ULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x00FF00FF00FF00FFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xCCCC3333CCCC3333ULL,
        0x5555555555555555ULL,
    },
    {
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFF0000FFFF0000ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x0F0F0F0F0F0F0F0FULL,
        0x0000000000000000ULL,
        0x55AA55AA55AA55AAULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x00FF00FF00FF00FFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xCCCC3333CCCC3333ULL,
        0x5555555555555555ULL,
    },
    {
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000FFFF0000FFFFULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x0F0F0F0F0F0F0F0FULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xAA55AA55AA55AA55ULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000000000000000ULL,
        0x00FF00FF00FF00FFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xCCCC3333CCCC3333ULL,
        0x5555555555555555ULL,
    },
    {
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000FFFF0000FFFFULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x0F0F0F0F0F0F0F0FULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x55AA55AA55AA55AAULL,
        0x0F0F0F0FF0F0F0F0ULL,
        0x0000000000000000ULL,
        0x00FF00FF00FF00FFULL,
        0xF0F0F0F0F0F0F0F0ULL,
        0xCCCC3333CCCC3333ULL,
        0x5555555555555555ULL,
    },
};

#endif /* __A64_CONSTS_H */
