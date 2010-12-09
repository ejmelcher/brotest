%include binpac.pac
%include bro.pac

analyzer Sebek withcontext {
        connection:     Sebek_Conn;
        flow:           Sebek_Flow;
};

%include sebek-protocol.pac
%include sebek-analyzer.pac