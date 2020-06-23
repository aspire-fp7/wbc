#include "WBAES.h"

void decrypt_fn(W128b& state) {
    _Pragma("ASPIRE begin protection(publicwbc,renewable)")
    _Pragma("ASPIRE end")
    #include "WBTables.h"

    wbaes.decrypt(state);
}
