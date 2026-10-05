/* QEMU MPS2-AN386 (Cortex-M4): 4 MiB SSRAM1 at 0 holds the image, and
   4 MiB SSRAM2/3 at 0x20000000 holds data, heap and stack. */
MEMORY
{
  FLASH : ORIGIN = 0x00000000, LENGTH = 4M
  RAM   : ORIGIN = 0x20000000, LENGTH = 4M
}
