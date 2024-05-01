# Progetto ODC
 - Fino all’ultimo appello di settembre
 - rimaniamo in contatto su slack

Programma che comprende tutte le normali funzioni vulnerabili alla format string. Per ogni chiamata tu devi capire, a livello di analisi statica, se il parametro della stringa che finisce all'interno della funzione arrivata da .rodata oppure no. Una qualsiasi sezione scrivibile dal binary andrebbe bene.

Guarda prima all'interno del CFG block corrente e poi analizza quelli precedenti.

Inoltre devi predisporre anche una interfaccia che ti faccia selezionare le diverse architetture, in modo da associare il registro giusto con la giusta ABI.

Python con angr e pyvex: traduce assembly in una rappr intermedia più semplice. Questo tool inoltre raggruppa molte istruzioni assembly in una sola istruzione intermedia più semplice (es: add, addi, add64.. diventano tutte solo add)

Primo parametro all’eseguibile è il path del binario e mi tira fuori le vulnerabilità
Secondo parametro è l'architettura

Si dovrà testare il tool con un database di programmi vulnerabili con format string e fare un'analisi di quanti hanno risposto bene e quanti hanno risposto male e anche perchè hanno risposto male

Eventualmente migliorare il programma aggiungendo una funzionalità che segue i puntatori [ ]

Stai leggendo la documentazione di angr. Sei arrivato qui: https://docs.angr.io/en/latest/analyses/cfg.html

The program might good to be:
 - [Common Weakness Enumeration (CWE)-compatible](http://cwe.mitre.org/)
 - [CII Best Practices "passing" badge](https://www.bestpractices.dev/en)

[This is nice tool you can take inspiration from](https://dwheeler.com/flawfinder/)

## Things to do
 - Create a test program, with different types of format string vulnerabilities and analyze what is found and what is not
 - Creare un codice semplice che abbia una format string vulnerability, studiare l'assembly e cercare di aprirlo con angr.
  
## Possibile algoritmo
 - Costruisco il CFG dell'eseguibile
 - controllo i simboli dell'eseguibile e cerco se c'è un simbolo con un nome che mi interessa (funzioni vulnerabili)
 - Vado in tutti i punti dell'eseguibile in cui c'è una call ai miei simboli
 - Costruisco il basic block a quegli indirizzi e controllo il valore dei registri andando indietro
 - 

## Format String Vulnerable Functions
[f]printf(), [v]snprintf(), and syslog()

## Angr graph dependencies
 - VSA_DDG: VFG. It is a DDG based on VSA states (no symbolic values)
 - CDG: CFG.
 - VFG: CFG. It is a CFG with static analysis on top of it
 - CFB: A Control-Flow Blanket is a representation for storing all instructions, data entries, and bytes of a full program.
 - CFGFast: Create CFG. If you give startAddress it will be better. A custom analysis, called GirlScout, is specifically made to recover the base address of a binary blob. After the base address is determined, you may want to reload the binary with the new base address by creating a new Project object, and then re-recover the CFG.
 - DDG: CFGFor a better data dependence graph, please consider performing a better static analysis first (like Value-set Analysis), and then construct a dependence graph on top of the analysis result (for example, the VFG in angr).
The DDG is based on a CFG, which should ideally be a CFGEmulated generated with the following options:
keep_state=True to keep all input states
state_add_options=angr.options.refs to store memory, register, and temporary value accesses
You may want to consider a high value for context_sensitivity_level as well when generating the CFG.
Also note that since we are using states from CFG, any improvement in analysis performed on CFG (like a points-to analysis) will directly benefit the DDG.
 - BackwardSlice: CFG
 - BoyScout: Try to determine the architecture and endieness of a binary blob
 - CompleteCallingConvention: Implements full-binary calling convention analysis. During the initial analysis of a binary, you may set recover_variables to True so that it will perform variable recovery on each function before performing calling convention analysis.
 - 


