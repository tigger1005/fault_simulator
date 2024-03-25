```Mermaid
---
title: Fault simulation with unicorn
---
classDiagram
    Main --> ElfFile
    Main --> Simulation
    Main --> Disassembly
    Main --> Fault_Attacks
    Cpu --o Simulation
    Fault_Attacks --> Simulation
    Unicorn --o Cpu
    Callbacks --> Unicorn
    CpuState --o Unicorn
    class Main {
        cs: Disassembly
        file_data: ElfFile
    }
    class Simulation{
        file_data: ElfFile
        emu: Cpu
        new()
        check_program()
        init_and_load()
        run()
        run_with_faults()
    }
    class Cpu{
        emu: Unicorn[CpuState]
        program_data: u64
    }
    class CpuState{
        state: RunState
        start_trace: bool
        with_register_data: bool
        negative_run: bool
        deactivate_print: bool
        trace_data: Vec[TraceRecord]
        fault_data: Vec[FaultData]
    }
    class Unicorn{
        data: SimulationData
    }
    class ElfFile{
    }
    class Callbacks{

    }
    class Disassembly{

    }
    class Fault_Attacks{
        cached_nop_simulation()
        cached_nop_simulation_2()
        cached_bit_flip_simulation()
    }

```