int tpm2_pcr_supported(void);
int tpm2_pcr_read(const char *algo_name, uint32_t pcr_handle, uint8_t *hwpcr,
		 int len, char **errmsg);
