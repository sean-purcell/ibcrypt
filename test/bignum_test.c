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
	const uint32_t sizes[] = {  32,  64 , 511, 256, 2048, 4096 };
	const uint32_t tests[] = { 100, 100 ,  10,  50,   4,    2 };

	/* create bc process to check our answers */
	pid_t bc;
	FILE *bcin;
	FILE *bcout;
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
	}

	bnu_free(&a);
	bnu_free(&b);
	bnu_free(&r);

	fclose(bcin);
	fclose(bcout);

	int status;
	waitpid(bc, &status, 0);
}

static void bn_div_test() {
	
}

void bignum_tests() {
	bn_mul_test();
}

