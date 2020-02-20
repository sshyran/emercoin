#include "rpc/server.h"
#include "utilstrencodings.h"
#include "validation.h"
#include "timedata.h"
#include "wallet/wallet.h"
#include "chainparams.h"


using namespace std;

UniValue color_new(const JSONRPCRequest& request)
{
    if (request.fHelp  || request.params.size() < 2 || request.params.size() > 3)
        throw runtime_error(
                "color_new <color> <amount> [address]\n"
                + HelpRequiringPassphrase());

    if (IsInitialBlockDownload())
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Emercoin is downloading blocks...");

    CMutableTransaction tmpTx;
    tmpTx.nTime = GetAdjustedTime();
    CWalletTx wtx(pwalletMain, MakeTransactionRef(std::move(tmpTx)));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    string strAddress = request.params.size() > 2 ? request.params[2].get_str() : "";

    return NullUniValue;
}

UniValue color_update(const JSONRPCRequest& request)
{
    if (request.fHelp)
        throw runtime_error(
                "color_update <color> <amount>\n"
                + HelpRequiringPassphrase());

    if (IsInitialBlockDownload())
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Emercoin is downloading blocks...");

    return NullUniValue;
}

UniValue color_delete(const JSONRPCRequest& request)
{
    if (request.fHelp)
        throw runtime_error(
                "color_delete <color>\n"
                + HelpRequiringPassphrase());

    if (IsInitialBlockDownload())
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Emercoin is downloading blocks...");

    return NullUniValue;
}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
  { "wallet",             "color_new",                &color_new,                false,  {} },
  { "wallet",             "color_update",             &color_update,             false,  {} },
  { "wallet",             "color_delete",             &color_delete,             false,  {} },
};


void RegisterColorCoinRPCCommands(CRPCTable &t)
{
    if (!IsV8Enabled(chainActive.Tip(), Params().GetConsensus()))
        return;

    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
