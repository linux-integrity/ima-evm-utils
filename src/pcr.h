int tpm2_pcr_supported(void);
int tpm2_pcr_read(const char *algo_name, int idx, uint8_t *hwpcr,
		 int len, char **errmsg);
