//============================================================================
// Name        : test_AEStblSpeed.cpp
// Author      : Dusan Klinec (ph4r05)
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C, Ansi-style
// *  Author: Dusan Klinec (ph4r05)
// *
// *  License: GPLv3 [http://www.gnu.org/licenses/gpl-3.0.html]
//============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <iomanip>
#include <cstdlib>
#include <ctime>
#include <cmath>
#include <vector>
#include <iostream>
#include <fstream>

#include "NTLUtils.h"
#include "MixingBijections.h"
#include "WBAES.h"
#include "WBAESGenerator.h"

using namespace std;

int tryMain(int argc, const char * argv[]);
void decrypt_fn(W128b& state);

int main(int argc, const char * argv[]) {
    return tryMain(argc, argv);
}

int tryMain(int argc, const char * argv[]) {
        time_t start=0, end=0;
        bool useExternal = false;
        int benchgen=0;
        int benchbge=0;
        bool randomKey=false;
        bool decrypt=false;
        std::string outFile = "decrypted_file";
        std::string outTables = "";
        std::string inTables = "";
        std::string aesKey = "";
        unsigned char keyFromString[AES_BYTES];

        _Pragma("ASPIRE begin protection(publicwbc,renewable)")
        _Pragma("ASPIRE end")
        #include "WBTables.h"

        // input parameters processing

        inTables = "encrypted.inputfile.tables";

        // use external coding ?
        useExternal = true;
        decrypt = true;
        
        //
        // AES encryption - encrypt input files with table representation
        //
        std::vector<std::string>  files = { "encrypted.inputfile.todecode" };
        for(std::string file : files){
            std::cout << "Input file " << file << std::endl;
        }

        //
        // Encryption with WB AES time test
        //
        WBAESGenerator generator;
        //WBAES * genAES = new WBAES;
        //ExtEncoding coding;
        // Generate new encoding.
#if 0 /* BART TODO */
        cout << "Generating External encoding, identity: " << useExternal << "..." << endl;
        generator.generateExtEncoding(&coding, useExternal ? 0 : WBAESGEN_EXTGEN_ID);
#endif
        
#if 0
        cout << "Loading stored AES tables: " << useExternal << endl;
        time(&start);
        generator.load(inTables.c_str(), genAES, &coding);
        time(&end);
        cout << "Loading AES tables took: [" << (end - start) << "] seconds" << endl;
#endif

        // open the given file
        std::string fileName = files[0];
        cout << "Going to " << (decrypt ? "decrypt":"encrypt") << " file ["<<fileName<<"] with WBAES" << endl;
        
        bool writeOut = !outFile.empty();
        ofstream out;
        if (writeOut){
            out.open(outFile.c_str(), ios::out | ios::binary | ios::trunc);
        }
        
        // Open reading file
        ifstream inf(fileName.c_str(), ios::in | ios::binary);
        if (inf.is_open()==false){
            cerr << "Cannot open specified input file" << endl;
            exit(3);
        }
        
        // read the file
        const int buffSize       = 4096;
        const long int iters     = buffSize / N_BYTES;
        unsigned long long blockCount = 0;
        char * memblock          = new char[buffSize];
        char blockbuff[N_BYTES];
        
        // time measurement of just the cipher operation
        time_t cstart, cend;
        time_t cacc=0;
        
        clock_t pstart, pend;
        clock_t pacc = 0;
        
        // measure the time here
        time(&start);
        do {
            streamsize bRead;
            
            // read data from the file to the buffer
            inf.read(memblock, buffSize);
            bRead = inf.gcount();
            if (inf.bad()) {
                std::cout << "badBit. Bytes read:" << bRead << " could be read";
                break;
            }
            
            // here we have data in the buffer - lets encrypt them
            W128b state;
            long int iter2comp = min(iters, (long int) ceil((float)bRead / N_BYTES));
            
            for(int k = 0; k < iter2comp; k++, blockCount++){
                arr_to_W128b(memblock, k * 16UL, state);
                
                // encryption
                // if (useExternal) generator.applyExternalEnc(state, &coding, true); /* TODO BART */
                
                time(&cstart);
                pstart = clock();
                if (decrypt){
                    decrypt_fn(state);
                } else {
                    assert(0);
                }
                
                pend = clock();
                time(&cend);
                
                cacc += (cend - cstart);
                pacc += (pend - pstart);
                
                // if (useExternal) generator.applyExternalEnc(state, &coding, false);  /* TODO BART */
                
                // if wanted, store to file
                if (writeOut){
                    W128b_to_arr(blockbuff, 0, state);
                    out.write(blockbuff, N_BYTES);
                }
            }
            
            if (inf.eof()){
                cout << "Finished reading the file " << endl;
                break;
            }
        } while(true);
        time(&end);
        
        time_t total = end-start;
        cout << "Encryption ended in ["<<total<<"]s; Pure encryption took ["<<((float) pacc / CLOCKS_PER_SEC)
        <<"] s (clock call); time: ["<<cacc<<"] s; encrypted ["<<blockCount<<"] blocks" << endl;
        
        // free allocated memory
        delete[] memblock;
        // close reading file
        inf.close();
        // close output writing file
        if (writeOut){
            out.flush();
            out.close();
        }
    return 0;
}
