/*
 * SPDX-FileCopyrightText: 2017-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "soc/soc.h"
#include "soc/interrupt_reg.h"
#include "riscv/rvruntime-frames.h"
#include "soc/soc_caps.h"
#include "sdkconfig.h"
#include "esp_private/vectors_const.h"
#include "esp_private/panic_reason.h"

#define STORE                   sw
#define LOAD                    lw
#define REGBYTES                4

    .equ SAVE_REGS, 32
    .equ CONTEXT_SIZE, (SAVE_REGS * 4)
    .equ EXC_ILLEGAL_INSTRUCTION, 0x2
    .equ panic_from_exception, xt_unhandled_exception
    .equ panic_from_isr, panicHandler

#if ( SOC_CPU_COPROC_NUM > 0 )
    /* Targets with coprocessors present a special CSR to get Illegal Instruction exception reason */
    .equ EXT_ILL_CSR, 0x7F0
#endif /* SOC_CPU_COPROC_NUM > 0 */

/* Macro which first allocates space on the stack to save general
 * purpose registers, and then save them. GP register is excluded.
 * The default size allocated on the stack is CONTEXT_SIZE, but it
 * can be overridden. */
.macro save_general_regs cxt_size=CONTEXT_SIZE
    addi sp, sp, -\cxt_size
    sw   ra, RV_STK_RA(sp)
    sw   tp, RV_STK_TP(sp)
    sw   t0, RV_STK_T0(sp)
    sw   t1, RV_STK_T1(sp)
    sw   t2, RV_STK_T2(sp)
    sw   s0, RV_STK_S0(sp)
    sw   s1, RV_STK_S1(sp)
    sw   a0, RV_STK_A0(sp)
    sw   a1, RV_STK_A1(sp)
    sw   a2, RV_STK_A2(sp)
    sw   a3, RV_STK_A3(sp)
    sw   a4, RV_STK_A4(sp)
    sw   a5, RV_STK_A5(sp)
    sw   a6, RV_STK_A6(sp)
    sw   a7, RV_STK_A7(sp)
    sw   s2, RV_STK_S2(sp)
    sw   s3, RV_STK_S3(sp)
    sw   s4, RV_STK_S4(sp)
    sw   s5, RV_STK_S5(sp)
    sw   s6, RV_STK_S6(sp)
    sw   s7, RV_STK_S7(sp)
    sw   s8, RV_STK_S8(sp)
    sw   s9, RV_STK_S9(sp)
    sw   s10, RV_STK_S10(sp)
    sw   s11, RV_STK_S11(sp)
    sw   t3, RV_STK_T3(sp)
    sw   t4, RV_STK_T4(sp)
    sw   t5, RV_STK_T5(sp)
    sw   t6, RV_STK_T6(sp)
.endm

.macro save_mepc
    csrr t0, mepc
    sw   t0, RV_STK_MEPC(sp)
.endm

/* Restore the general purpose registers (excluding gp) from the context on
 * the stack. The context is then deallocated. The default size is CONTEXT_SIZE
 * but it can be overridden. */
.macro restore_general_regs cxt_size=CONTEXT_SIZE
    lw   ra, RV_STK_RA(sp)
    lw   tp, RV_STK_TP(sp)
    lw   t0, RV_STK_T0(sp)
    lw   t1, RV_STK_T1(sp)
    lw   t2, RV_STK_T2(sp)
    lw   s0, RV_STK_S0(sp)
    lw   s1, RV_STK_S1(sp)
    lw   a0, RV_STK_A0(sp)
    lw   a1, RV_STK_A1(sp)
    lw   a2, RV_STK_A2(sp)
    lw   a3, RV_STK_A3(sp)
    lw   a4, RV_STK_A4(sp)
    lw   a5, RV_STK_A5(sp)
    lw   a6, RV_STK_A6(sp)
    lw   a7, RV_STK_A7(sp)
    lw   s2, RV_STK_S2(sp)
    lw   s3, RV_STK_S3(sp)
    lw   s4, RV_STK_S4(sp)
    lw   s5, RV_STK_S5(sp)
    lw   s6, RV_STK_S6(sp)
    lw   s7, RV_STK_S7(sp)
    lw   s8, RV_STK_S8(sp)
    lw   s9, RV_STK_S9(sp)
    lw   s10, RV_STK_S10(sp)
    lw   s11, RV_STK_S11(sp)
    lw   t3, RV_STK_T3(sp)
    lw   t4, RV_STK_T4(sp)
    lw   t5, RV_STK_T5(sp)
    lw   t6, RV_STK_T6(sp)
    addi sp,sp, \cxt_size
.endm

.macro restore_mepc
    lw      t0, RV_STK_MEPC(sp)
    csrw    mepc, t0
.endm


    .global rtos_int_enter
    .global rtos_int_exit
    .global rtos_save_fpu_coproc
    .global _global_interrupt_handler
#ifdef CONFIG_ESP_SYSTEM_GDBSTUB_RUNTIME
    .global gdbstub_handle_debug_int
#endif

    .section .exception_vectors.text

    /* Exception handler.*/
    .type _panic_handler, @function
    .global _panic_handler
_panic_handler:
    /* Allocate space on the stack and store general purpose registers */
    save_general_regs RV_STK_FRMSZ

    /* As gp register is not saved by the macro, save it here */
    sw    gp, RV_STK_GP(sp)

    /* Same goes for the SP value before trapping */
    addi  t0, sp, RV_STK_FRMSZ /* restore sp with the value when trap happened */

    /* Save CSRs */
    sw    t0, RV_STK_SP(sp)
    csrr  t0, mepc
    sw    t0, RV_STK_MEPC(sp)
    csrr  t0, mstatus
    sw    t0, RV_STK_MSTATUS(sp)
    csrr  t0, mtvec
    sw    t0, RV_STK_MTVEC(sp)
    csrr  t0, mhartid
    sw    t0, RV_STK_MHARTID(sp)
    csrr  t0, mtval
    sw    t0, RV_STK_MTVAL(sp)

    /* Keep mcause in s0, only the exception code and interrupt bit are relevant */
    csrr  s0, mcause
    li    t1, VECTORS_MCAUSE_INTBIT_MASK | VECTORS_MCAUSE_REASON_MASK
    and   s0, s0, t1

#if ( SOC_CPU_COPROC_NUM > 0 )
    /* Check if the exception was cause by a coprocessor instruction. If this is the case, we have
     * to lazily save the registers inside the current owner's save area */
    /* Check if the exception is Illegal instruction */
    li    a1, EXC_ILLEGAL_INSTRUCTION
    bne   s0, a1, _panic_handler_not_coproc
    /* In case this is due to a coprocessor, set ra right now to simplify the logic below */
    la    ra, _return_from_exception
    /* EXT_ILL CSR should contain the reason for the Illegal Instruction. */
    csrr  a0, EXT_ILL_CSR
    bnez  a0, _panic_handler_coproc
#if SOC_CPU_HAS_FPU_EXT_ILL_BUG && SOC_CPU_HAS_FPU
    /* If the SOC present the hardware EXT_ILL CSR bug, it doesn't support FPU load/store detection
     * so we have to check the instruction's opcode (in `mtval` = `t0`) */
    andi  a0, t0, 0b1011111
    li    a1, 0b0000111
    /* If opcode is of the form 0b0x00111, the instruction is FLW or FSW */
    beq   a0, a1, rtos_save_fpu_coproc
    /* Check the compressed instructions: C.FLW, C.FSW, C.FLWSP and C.FSWP.
     * All of them have their highest 3 bits to x11 and the lowest bit to 0 */
    li    a0, 0x6001
    and   a0, t0, a0    /* a0 = mtval & 0x6001 */
    li    a1, 0x6000
    beq   a0, a1, rtos_save_fpu_coproc
    /* The instruction was not an FPU one, continue the exception */
#endif /* SOC_CPU_HAS_FPU_EXT_ILL_BUG && SOC_CPU_HAS_FPU */
    j _panic_handler_not_coproc
_panic_handler_coproc:
    /* EXT_ILL CSR reasons are stored as follows:
     * - Bit 0: FPU core instruction (Load/Store instructions NOT concerned)
     * - Bit 1: Low-power core
     * - Bit 2: PIE core
     */
#if SOC_CPU_HAS_FPU
    li    a1, 1
    beq   a0, a1, rtos_save_fpu_coproc
#endif /* SOC_CPU_HAS_FPU */
    /* Ignore LP and PIE for now, continue the exception */
_panic_handler_not_coproc:
#endif /* ( SOC_CPU_COPROC_NUM > 0 ) */

    /* Call panic_from_exception(sp) or panic_from_isr(sp)
     * depending on whether we have a pseudo excause or not.
     * If mcause's highest bit is 1, then an interrupt called this routine,
     * so we have a pseudo excause. Else, it is due to a exception, we don't
     * have an pseudo excause */
    mv    a0, sp
    mv    a1, s0

    /* Branches instructions don't accept immediate values, so use t1 to
     * store our comparator */
    li    t0, 0x80000000
    bgeu  a1, t0, _call_panic_handler
    sw    a1, RV_STK_MCAUSE(sp)
#ifdef CONFIG_ESP_SYSTEM_GDBSTUB_RUNTIME
    li    t0, 3
    beq   a1, t0, _call_gdbstub_handler
#endif
    call  panic_from_exception
    /* We arrive here if the exception handler has returned. */
    j     _return_from_exception

#ifdef CONFIG_ESP_SYSTEM_GDBSTUB_RUNTIME
_call_gdbstub_handler:
    call  gdbstub_handle_debug_int
    j     _return_from_exception
#endif

_call_panic_handler:
    /* Remove highest bit from mcause (a1) register and save it in the structure */
    not   t0, t0
    and   a1, a1, t0
#if CONFIG_SOC_INT_CLIC_SUPPORTED
    /* When CLIC is supported, external interrupts are shifted by 16, deduct this difference from mcause */
    add   a1, a1, -16
#endif // CONFIG_SOC_INT_CLIC_SUPPORTED

#if CONFIG_ESP_INT_WDT_CHECK_CPU1
    /* Check if this was a INT WDT */
    li t0, PANIC_RSN_INTWDT_CPU0
    bne a1, t0, _store_mcause
    /* Check if the cause is the app cpu failing to tick, if so then update mcause to reflect this*/
    lw t0, int_wdt_cpu1_ticked
    bnez t0, _store_mcause
    li t0, PANIC_RSN_INTWDT_CPU1_FLAG
    add a1, a1, t0
#endif

_store_mcause:
    sw    a1, RV_STK_MCAUSE(sp)
    call  panic_from_isr
    /* We arrive here if the exception handler has returned. This means that
     * the exception was handled, and the execution flow should resume.
     * Restore the registers and return from the exception.
     */
_return_from_exception:
    restore_mepc
    /* MTVEC and SP are assumed to be unmodified.
     * MSTATUS, MHARTID, MTVAL are read-only and not restored.
     */
    lw gp,  RV_STK_GP(sp)
    restore_general_regs RV_STK_FRMSZ
    mret
    .size  _panic_handler, .-_panic_handler


    /* This is the interrupt handler.
     * It saves the registers on the stack, prepares for interrupt nesting, re-enables the interrupts,
     * then jumps to the C dispatcher in interrupt.c. Upon return, the register context will be restored
     * from the stack.
     */
    .global _interrupt_handler
    .type _interrupt_handler, @function
#ifndef CONFIG_IDF_RTOS_RTTHREAD

_interrupt_handler:
    /* Start by saving the general purpose registers and the PC value before
     * the interrupt happened. */
    save_general_regs
    save_mepc

    /* Though it is not necessary we save GP and SP here.
     * SP is necessary to help GDB to properly unwind
     * the backtrace of threads preempted by interrupts (OS tick etc.).
     * GP is saved just to have its proper value in GDB. */
    /* As gp register is not saved by the macro, save it here */
    sw      gp, RV_STK_GP(sp)
    /* Same goes for the SP value before trapping */
    addi    a0, sp, CONTEXT_SIZE /* restore sp with the value when interrupt happened */

    /* Save SP former value */
    sw      a0, RV_STK_SP(sp)

    /* Notify the RTOS that an interrupt ocurred, it will save the current stack pointer
     * in the running TCB, no need to pass it as a parameter */
    call    rtos_int_enter
    /* If this is a non-nested interrupt, SP now points to the interrupt stack */

    /* Before dispatch c handler, restore interrupt to enable nested intr */
    csrr    s1, mcause
    csrr    s2, mstatus

#if !SOC_INT_HW_NESTED_SUPPORTED
    /* Save the interrupt threshold level */
    li      t0, INTERRUPT_CURRENT_CORE_INT_THRESH_REG
    lw      s3, 0(t0)

    /* Increase interrupt threshold level */
    li      t2, VECTORS_MCAUSE_REASON_MASK
    and     t1, s1, t2       /* t1 = mcause & mask */
    slli    t1, t1, 2        /* t1 = mcause * 4 */
    li      t2, INTC_INT_PRIO_REG(0)
    add     t1, t2, t1       /* t1 = INTC_INT_PRIO_REG + 4 * mcause */
    lw      t2, 0(t1)        /* t2 = INTC_INT_PRIO_REG[mcause] */
    addi    t2, t2, 1        /* t2 = t2 +1 */
    sw      t2, 0(t0)        /* INTERRUPT_CURRENT_CORE_INT_THRESH_REG = t2 */
    fence
#endif // !SOC_INT_HW_NESTED_SUPPORTED

    csrsi   mstatus, 0x8
    /* MIE set. Nested interrupts can now occur */

    #ifdef CONFIG_PM_TRACE
    li      a0, 0       /* = ESP_PM_TRACE_IDLE */
    #if SOC_CPU_CORES_NUM == 1
    li      a1, 0       /* No need to check core ID on single core hardware */
    #else
    csrr    a1, mhartid
    #endif
    la      t0, esp_pm_trace_exit
    jalr    t0          /* absolute jump, avoid the 1 MiB range constraint */
    #endif

    #ifdef CONFIG_PM_ENABLE
    la      t0, esp_pm_impl_isr_hook
    jalr    t0          /* absolute jump, avoid the 1 MiB range constraint */
    #endif

    /* call the C dispatcher */
    mv      a0, sp      /* argument 1, stack pointer */
    mv      a1, s1      /* argument 2, interrupt number (mcause) */
    /* mask off the interrupt flag of mcause */
    li	    t0, VECTORS_MCAUSE_REASON_MASK
    and     a1, a1, t0
    jal     _global_interrupt_handler

    /* After dispatch c handler, disable interrupt to make freertos make context switch */

    csrci   mstatus, 0x8
    /* MIE cleared. Nested interrupts are disabled */

#if !SOC_INT_HW_NESTED_SUPPORTED
    /* restore the interrupt threshold level */
    li      t0, INTERRUPT_CURRENT_CORE_INT_THRESH_REG
    sw      s3, 0(t0)
    fence
#endif // !SOC_INT_HW_NESTED_SUPPORTED

    /* The RTOS will restore the current TCB stack pointer. This routine will preserve s1 and s2.
     * Returns the new `mstatus` value. */
    mv      a0, s2      /* a0 = mstatus */
    call    rtos_int_exit

    /* Restore the rest of the registers.
     * In case the target uses the CLIC, it is mandatory to restore `mcause` register since it contains
     * the former CPU priority. When executing `mret`, the hardware will restore the former threshold,
     * from `mcause` to `mintstatus` CSR */
    csrw    mcause, s1
    csrw    mstatus, a0
    restore_mepc
    restore_general_regs
    /* exit, this will also re-enable the interrupts */
    mret
    .size  _interrupt_handler, .-_interrupt_handler
#else
_interrupt_handler:
    /* 此时CPU的sp = from_thread->sp */
    /* 注意： 在这里，并没有将mepc的值赋值为from_thread栈中的epc，但后面会赋值 */
    addi sp, sp, -32 * REGBYTES             /* sp = sp - 32 * 4 栈指针向下偏移32个寄存器长度，用来将CPU的寄存器保存到from_thread的栈中*/
    STORE x1,   1 * REGBYTES(sp)            /* 将CPU的x1寄存器，即ra寄存器，保存到from_thread->栈中 */

    li    t0,   0x80                        /* t0 = 0x80 */
    STORE t0,   2 * REGBYTES(sp)            /* mstatus = t0, 即关闭全局中断 */

    /* 将 CPU 的其他寄存器的值，保存到from_thread的任务栈中 */
    STORE x4,   4 * REGBYTES(sp)
    STORE x5,   5 * REGBYTES(sp)
    STORE x6,   6 * REGBYTES(sp)
    STORE x7,   7 * REGBYTES(sp)
    STORE x8,   8 * REGBYTES(sp)
    STORE x9,   9 * REGBYTES(sp)
    STORE x10, 10 * REGBYTES(sp)
    STORE x11, 11 * REGBYTES(sp)
    STORE x12, 12 * REGBYTES(sp)
    STORE x13, 13 * REGBYTES(sp)
    STORE x14, 14 * REGBYTES(sp)
    STORE x15, 15 * REGBYTES(sp)
    STORE x16, 16 * REGBYTES(sp)
    STORE x17, 17 * REGBYTES(sp)
    STORE x18, 18 * REGBYTES(sp)
    STORE x19, 19 * REGBYTES(sp)
    STORE x20, 20 * REGBYTES(sp)
    STORE x21, 21 * REGBYTES(sp)
    STORE x22, 22 * REGBYTES(sp)
    STORE x23, 23 * REGBYTES(sp)
    STORE x24, 24 * REGBYTES(sp)
    STORE x25, 25 * REGBYTES(sp)
    STORE x26, 26 * REGBYTES(sp)
    STORE x27, 27 * REGBYTES(sp)
    STORE x28, 28 * REGBYTES(sp)
    STORE x29, 29 * REGBYTES(sp)
    STORE x30, 30 * REGBYTES(sp)
    STORE x31, 31 * REGBYTES(sp)

    /* 备份 CPU 的 sp (这时，CPU的sp其实就是from thread的sp指针) 寄存器的值到 s0 寄存器中，下面会使用s0，恢复 CPU 的寄存器 */
    move  s0, sp    /* s0 = sp */

    /* 在中断函数中，中断函数中调用的C函数，需要使用 sp， 这里，在中断函数中，使用的 sp 为，系统的栈资源 */
    /* switch to interrupt stack */
    la    sp, __stack_end__   /* sp = _sp */

    /* interrupt handle */
    /* 注意： 在调用C函数之前,比如sp的值为0x30001000, 在执行完C函数后，sp的值还是会变成 0x30001000 */
    call  rt_interrupt_enter    /* 执行所有的中断函数前，调用该函数 */

    csrr s1, mcause
	csrr s2, mstatus

    /* Save the interrupt threshold level */
	la t0, INTERRUPT_CORE0_CPU_INT_THRESH_REG
	lw s3, 0(t0)

    li t2, 0x7fffffff
	and t1, s1, t2		/* t1 = mcause & mask */
	slli t1, t1, 2 		/* t1 = mcause * 4 */
	la t2, INTC_INT_PRIO_REG(0)
	add t1, t2, t1		/* t1 = INTC_INT_PRIO_REG + 4 * mcause */
	lw t2, 0(t1)		/* t2 = INTC_INT_PRIO_REG[mcause] */
	addi t2, t2, 1		/* t2 = t2 +1 */
	sw t2, 0(t0)		/* INTERRUPT_CORE0_CPU_INT_THRESH_REG = t2 */
	fence

    li t0, 0x8
	csrrs t0, mstatus, t0

    /* call the C dispatcher */
	mv      a0, sp      /* argument 1, stack pointer */
	mv      a1, s1      /* argument 2, interrupt number (mcause) */
	/* mask off the interrupt flag of mcause */
	li	    t0, 0x7fffffff
	and     a1, a1, t0
	jal     _global_interrupt_handler

    li t0, 0x8
	csrrc t0, mstatus, t0

	/* restore the interrupt threshold level */
	la t0, INTERRUPT_CORE0_CPU_INT_THRESH_REG
	sw s3, 0(t0)
	fence

    call  rt_interrupt_leave    /* 执行所有的中断函数后，调用该函数 */

    /* 上面，将保存执行中断服务函数之前的CPU的sp寄存器到了s0所指向的位置处，当执行完中断服务函数，需要将之前的CPU寄存器，恢复一下,此时sp又变成了from thread的sp了 */
    move  sp, s0    /* sp = s0 */

    /* 下面两句话，相当于将 rt_thread_switch_interrupt_flag 值，赋值给了s2  */
    /* 将 rt_thread_switch_interrupt_flag 的地址值，赋值给 s0 寄存器*/
    la    s0, rt_thread_switch_interrupt_flag       /* s0 = &rt_thread_switch_interrupt_flag */
    /* 将 s0 所指向的地址处的内容，取出来，赋值给 s2 寄存器，其实就是将  rt_thread_switch_interrupt_flag 的值，赋值给了 s2 寄存器*/
    lw    s2, 0(s0)                 /* s2 = *s0 = rt_thread_switch_interrupt_flag */

    /* 如果 s2的值，即 rt_thread_switch_interrupt_flag 值，如果不为0，则需要继续执行下一条指令，如果为0，则需要跳转到 spurious_interrupt 标号处 执行 */
    /* 如果 s2的值等于0，rt_thread_switch_interrupt_flag等于0， 则不需要在中断处理函数中，进行上下文切换，反之则需要 */
    /* 如果不需要上下文切换， */

    /* 在这里，跳转到 spurious_interrupt的话，是不会进行上下文切换的，因为，此时CPU的sp指针还是from线程的*/
    beqz  s2, spurious_interrupt    /* if (s2 == 0) goto spurious_interrupt; else 执行下一条语句*/

    /* 需要上下文切换： 主要目的是将CPU的sp指针，赋值为to_thread的sp */

    /* 将 s0 所执向的地址的内容设置为0， 也就是，将变量 rt_thread_switch_interrupt_flag 赋值为了 0 */
    /* s0存放的值是 rt_thread_switch_interrupt_flag 变量的地址*/
    sw    zero, 0(s0)       /* *s0 = 0; 也就是 rt_thread_switch_interrupt_flag = 0 */
    /* 将 mepc 的值，赋值给 a0 寄存器，mepc 的值是，跳转到中断函数执行之前的 PC 指针 */
    /* 这时的mpec其实，还是from线程，在跳转到中断执行前的一个PC地址 */
    csrr  a0, mepc  /* a0 = mepc */

    /* 将 mpec 的值写回到freom thread任务栈中的 epc 中,待后续，恢复from线程时，使用 */
    STORE a0, 0 * REGBYTES(sp)  /* from_thread->sp->epc = a0 ，中断入口处*/

    /* 将from_thread的sp指针，赋值为CPU的sp指针 */
    la    s0, rt_interrupt_from_thread  /* s0 = &rt_interrupt_from_thread 注意： rt_interrupt_from_thread = &(from_thread->sp) */
    LOAD  s1, 0(s0)                     /* s1 = rt_interrupt_from_thread，也就是s1 = &(from_thread->sp) */
    STORE sp, 0(s1)                     /* from_thread->sp = sp*/

    /* 接下来，需要开始恢复CPU的sp为to_thread的sp了 */
    la    s0, rt_interrupt_to_thread    /* s0 = &rt_interrupt_to_thread 注意： rt_interrupt_to_thread = &(to_thred->sp)*/
    LOAD  s1, 0(s0)                     /* s1 = rt_interrupt_to_thread, 也就是s1 = &(to_thred->sp) */
    LOAD  sp, 0(s1)                     /* sp = (to_thred->sp)*/

    /* 将CPU的 mepc设置为to_thred的mepc，待中断退出，执行mret指令后，将从该地址开始执行 */
    LOAD  a0,  0 * REGBYTES(sp)         /* a0 = to_thread的mepc的值*/
    csrw  mepc, a0                      /* mepc = a0 */


spurious_interrupt:
    LOAD  x1,   1 * REGBYTES(sp)

    /* Remain in M-mode after mret */
    li    t0, 0x00001800
    csrs  mstatus, t0
    LOAD  t0,   2 * REGBYTES(sp)
    csrs  mstatus, t0

    LOAD  x4,   4 * REGBYTES(sp)
    LOAD  x5,   5 * REGBYTES(sp)
    LOAD  x6,   6 * REGBYTES(sp)
    LOAD  x7,   7 * REGBYTES(sp)
    LOAD  x8,   8 * REGBYTES(sp)
    LOAD  x9,   9 * REGBYTES(sp)
    LOAD  x10, 10 * REGBYTES(sp)
    LOAD  x11, 11 * REGBYTES(sp)
    LOAD  x12, 12 * REGBYTES(sp)
    LOAD  x13, 13 * REGBYTES(sp)
    LOAD  x14, 14 * REGBYTES(sp)
    LOAD  x15, 15 * REGBYTES(sp)
    LOAD  x16, 16 * REGBYTES(sp)
    LOAD  x17, 17 * REGBYTES(sp)
    LOAD  x18, 18 * REGBYTES(sp)
    LOAD  x19, 19 * REGBYTES(sp)
    LOAD  x20, 20 * REGBYTES(sp)
    LOAD  x21, 21 * REGBYTES(sp)
    LOAD  x22, 22 * REGBYTES(sp)
    LOAD  x23, 23 * REGBYTES(sp)
    LOAD  x24, 24 * REGBYTES(sp)
    LOAD  x25, 25 * REGBYTES(sp)
    LOAD  x26, 26 * REGBYTES(sp)
    LOAD  x27, 27 * REGBYTES(sp)
    LOAD  x28, 28 * REGBYTES(sp)
    LOAD  x29, 29 * REGBYTES(sp)
    LOAD  x30, 30 * REGBYTES(sp)
    LOAD  x31, 31 * REGBYTES(sp)

    addi  sp, sp, 32 * REGBYTES
    mret
	.size  _interrupt_handler, .-_interrupt_handler
#endif