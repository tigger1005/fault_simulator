OUTPUT_FORMAT("elf32-littlearm", "elf32-littlearm", "elf32-littlearm")
OUTPUT_ARCH(arm)

STACK_SIZE = 0x1000;

/* Define the memory regions */
MEMORY
{
  FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 256K
  RAM (rw)  : ORIGIN = 0x20000000, LENGTH = 64K
}


SECTIONS
{
	/* The program code and other data goes into FLASH */
	.text :
	{
		. = ALIGN(4);
		bin/aarch32/obj/entry.o (.text)
		*(.text)
	    *(.text*)          /* .text* sections (code) */
	} > FLASH


  	.rodata : {
		. = ALIGN(4);
		*(.rodata)         /* .rodata sections (constants, strings, etc.) */
    	*(.rodata*)        /* .rodata* sections (constants, strings, etc.) */
	} > FLASH

	/* The program data goes into RAM */
  	.data : {
		__data_start__ = .;
		*(.data)         /* .data sections */
    	*(.data*)        /* .data* sections */
		__data_end__ = .;
	} > RAM

	/* Uninitialized data section */
	.bss :
	{
		. = ALIGN(4);
		__bss_start__ = .;
		*(.bss)
		*(.bss*)
		*(COMMON)
		__bss_end__ = .;
	} > RAM

	/* Stack section */
  	.stack (NOLOAD) :
  	{
		. = ALIGN(16);
        . = ORIGIN(RAM) + LENGTH(RAM) - STACK_SIZE; /* Startadresse des Stacks */
        _estack = .;  /* Stack-Pointer initialisieren */
        . += STACK_SIZE; /* Größe des Stacks */
  	} > RAM

	  /* End of the program */
  	_end = .;
}
