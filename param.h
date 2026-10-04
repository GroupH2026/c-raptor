/******************************************************************************
 *
 * This code is written by Zhenfei Zhang @ OnboardSecurity
 *
 ******************************************************************************/
/*
 * param.h
 *
 *  Created on: May 15, 2018
 *      Author: zhenfei
 */

#ifndef PARAM_H_
#define PARAM_H_


#include "profile.h"

#define DIM RAPTOR_FALCON_DEGREE
#define PARAM_Q 12289

#define SEEDLEN 64

/* The params below are safe to override, e.g. `make NOU=10` */

#ifndef SIGMA
#define SIGMA   123     /* Legacy sampler value; unvalidated for the 1024 extension. */
#endif

#ifndef NOU
#define NOU     50      /* Number of users (ring size) */
#endif

#ifndef PARAM_NONCE
#define PARAM_NONCE     40
#endif

#endif /* PARAM_H_ */
