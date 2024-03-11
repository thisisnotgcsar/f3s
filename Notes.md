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

