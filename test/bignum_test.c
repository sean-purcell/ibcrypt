#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

#include <unistd.h>
#include <sys/wait.h>

#include <bignum.h>

static void bn_err(const char *err) {
	fprintf(stderr, "bignum lib error: %s\n", err);
	exit(1);
}

static void uppercase(char *str) {
	size_t len = strlen(str);
	size_t i;
	for(i = 0; i < len; i++) {
		str[i] = toupper(str[i]);
	}
}

/* initialize a bc subprocess for calculation */
static void init_bc(pid_t *pid, FILE **bcin, FILE **bcout) {
	int w_pipe[2];
	int r_pipe[2];

	if(pipe(w_pipe) != 0 || pipe(r_pipe) != 0) {
		fprintf(stderr, "pipe failed to happen");
		exit(1);
	}

	pid_t bc = fork();
	if(bc == 0) { /* we are the child */
		/* set up the pipes */
		dup2(w_pipe[0], STDIN_FILENO);
		dup2(r_pipe[1], STDOUT_FILENO);
		/* close unneeded pipe ends */
		close(w_pipe[1]);
		close(r_pipe[0]);
		/* become bc */
		setenv("BC_LINE_LENGTH", "1000000", 1);
		execlp("bc", "bc", NULL);
		/* if we get here, we failed */
		_exit(1);
	}

	/* we're the parent, close unneeded pipe ends and setup bc for base 16 */
	close(w_pipe[0]);
	close(r_pipe[1]);

	*bcin = fdopen(w_pipe[1], "w");
	*bcout = fdopen(r_pipe[0], "r");

	fprintf(*bcin, "ibase=16;obase=10;\n");
}

static void bn_mul_test() {
	const uint64_t sizes[] = {  32,  64 , 511, 256, 2048, 4096 };
	const uint64_t tests[] = { 100, 100 ,  10,  50,   4,    2 };

	/* create bc process to check our answers */
	pid_t bc;
	FILE *bcin, *bcout;
	init_bc(&bc, &bcin, &bcout);

	/* run tests */

	BIGNUM a = BN_ZERO;
	BIGNUM b = BN_ZERO;
	BIGNUM r = BN_ZERO;
	int i;
	for(i = 0; i < sizeof(sizes)/sizeof(sizes[0]); i++) {
		int j;
		const size_t numsize = (sizes[i] + 63) / 64 * 16;
		char *astr = malloc(numsize + 1);
		char *bstr = malloc(numsize + 1);
		char *res = malloc(numsize * 2 + 1);
		char *bcres = malloc(numsize * 2 + 2);
		for(j = 0; j < tests[i]; j++) {
			if(bni_rand_bits(&a, sizes[i]) != 0 ||
			   bni_rand_bits(&b, sizes[i]) != 0) {
				bn_err("rand");
			}

			if(bno_mul(&r, &a, &b) != 0) {
				bn_err("mul");
			}

			bnu_tstr(astr, &a);
			bnu_tstr(bstr, &b);
			bnu_tstr(res, &r);

			/* get bc to calculate the answer */
			uppercase(astr);
			uppercase(bstr);
			uppercase(res);

			fprintf(bcin, "%s*%s\n", astr, bstr);
			fflush(bcin);
			fgets(bcres, 1000000, bcout);
			bcres[strlen(bcres)-1] = '\0';

			/* compare */
			if(res[0] == '\0' ? !(bcres[0] == '0' && bcres[1] == '\0') /* result was 0 */
				: strcmp(&res[strlen(res)-strlen(bcres)], bcres) != 0) {
				printf("MUL FAILED:\n%s*%s=\n%s\n%s\n\n",
					astr, bstr, res, bcres);
			}
		}

		free(astr);
		free(bstr);
		free(res);
		free(bcres);
	}

	bnu_free(&a);
	bnu_free(&b);
	bnu_free(&r);

	fclose(bcin);
	fclose(bcout);

	int status;
	waitpid(bc, &status, 0);
}

static void bn_div_mod_test() {
	const uint64_t sizea[] = {  64, 256, 512, 2048, 2048, 4096 };
	const uint64_t sizeb[] = {  32, 128, 128, 1024, 1536, 2048 };
	const uint64_t tests[] = { 100, 100,  50,   10,   10,   10 };

	pid_t bc;
	FILE *bcin, *bcout;
	init_bc(&bc, &bcin, &bcout);

	BIGNUM a = BN_ZERO;
	BIGNUM b = BN_ZERO;
	BIGNUM q = BN_ZERO;
	BIGNUM r = BN_ZERO;
	int i;
	for(i = 0; i < sizeof(sizea)/sizeof(sizea[0]); i++) {
		int j;
		const size_t asize = (sizea[i] + 63) / 64 * 16;
		const size_t bsize = (sizeb[i] + 63) / 64 * 16;
		char *astr = malloc(asize + 1);
		char *bstr = malloc(bsize + 1);
		char *qstr = malloc(asize + 1);
		char *rstr = malloc(bsize + 1);
		char *bcq = malloc(asize + 1);
		char *bcr = malloc(bsize + 1);

		for(j = 0; j < tests[i]; j++) {
			if(bni_rand_bits(&a, sizea[i]) != 0 ||
			   bni_rand_bits(&b, sizeb[i]) != 0) {
				bn_err("rand");
			}

			if(bno_div_mod(&q, &r, &a, &b) != 0) {
				bn_err("div");
			}

			bnu_tstr(astr, &a);
			bnu_tstr(bstr, &b);
			bnu_tstr(qstr, &q);
			bnu_tstr(rstr, &r);

			/* compare answers with bc */
			uppercase(astr);
			uppercase(bstr);
			uppercase(qstr);
			uppercase(rstr);

			fprintf(bcin, "%s/%s\n%s%%%s\n", astr, bstr, astr, bstr);
			fflush(bcin);
			fgets(bcq, 1000000, bcout);
			fgets(bcr, 1000000, bcout);

			bcq[strlen(bcq)-1] = '\0';
			bcr[strlen(bcr)-1] = '\0';

			if(qstr[0] == '\0' ? !(bcq[0] == '0' && bcq[1] == '\0') /* result was 0 */
				: strcmp(&qstr[strlen(qstr)-strlen(bcq)], bcq) != 0) {
				printf("DIV FAILED:\n%s/%s=\n%s\n%s\n\n",
					astr, bstr, qstr, bcq);
			}
			if(rstr[0] == '\0' ? !(bcr[0] == '0' && bcr[1] == '\0') /* result was 0 */
				: strcmp(&rstr[strlen(rstr)-strlen(bcr)], bcr) != 0) {
				printf("MOD FAILED:\n%s/%s=\n%s\n%s\n\n",
					astr, bstr, rstr, bcr);
			}
		}

		free(astr);
		free(bstr);
		free(qstr);
		free(rstr);
		free(bcq);
		free(bcr);
	}

	bnu_free(&a);
	bnu_free(&b);
	bnu_free(&q);
	bnu_free(&r);

	fclose(bcin);
	fclose(bcout);

	int status;
	waitpid(bc, &status, 0);
}

int bno_barrett_rmod(BIGNUM *r, const BIGNUM *a, const BIGNUM *n);

static void bn_barrett_mod_test() {
	const uint64_t sizea[] = {  64, 256, 512, 2048, 2048, 4096 };
	const uint64_t sizeb[] = {  32, 192, 257, 1025, 1536, 3072 };
	const uint64_t tests[] = { 100, 100,  50,   10,   10,   10 };

	pid_t bc;
	FILE *bcin, *bcout;
	init_bc(&bc, &bcin, &bcout);

	/* run tests */

	BIGNUM a = BN_ZERO;
	BIGNUM b = BN_ZERO;
	BIGNUM r = BN_ZERO;
	int i, j;
	for(i = 0; i < sizeof(sizea)/sizeof(sizea[0]); i++) {
		const size_t asize = (sizea[i] + 63) / 64 * 16;
		const size_t bsize = (sizeb[i] + 63) / 64 * 16;
		char *astr = malloc(asize + 1);
		char *bstr = malloc(bsize + 1);
		char *rstr = malloc(bsize + 1);
		char *bcr = malloc(bsize + 1);

		for(j = 0; j < tests[i]; j++) {
			if(bni_rand_bits(&a, sizea[i]) != 0 ||
			   bni_rand_bits(&b, sizeb[i]) != 0) {
				bn_err("rand");
			}

			if(bno_barrett_rmod(&r, &a, &b) != 0) {
				bn_err("barrett rmod");
			}

			bnu_tstr(astr, &a);
			bnu_tstr(bstr, &b);
			bnu_tstr(rstr, &r);

			/* check answer against bc */
			uppercase(astr);
			uppercase(bstr);
			uppercase(rstr);

			fprintf(bcin, "%s%%%s\n", astr, bstr);
			fflush(bcin);
			fgets(bcr, 1000000, bcout);

			bcr[strlen(bcr)-1] = '\0';

			if(rstr[0] == '\0' ? !(bcr[0] == '0' && bcr[1] == '\0') /* result was 0 */
				: strcmp(&rstr[strlen(rstr)-strlen(bcr)], bcr) != 0) {
				printf("BARRETT RMOD FAILED:\n%s%%\n%s=\n%s\n%s\n\n",
					astr, bstr, rstr, bcr);
			}
		}

		free(astr);
		free(bstr);
		free(rstr);
		free(bcr);
	}

	bnu_free(&a);
	bnu_free(&b);
	bnu_free(&r);

	fclose(bcin);
	fclose(bcout);

	int status;
	waitpid(bc, &status, 0);
}

void bignum_tests() {
	bn_mul_test();
	bn_div_mod_test();
	bn_barrett_mod_test();
}

