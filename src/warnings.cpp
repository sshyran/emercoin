// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <warnings.h>

#include <sync.h>
#include <util/system.h>
#include <util/translation.h>

#include <checkpoints.h>

static RecursiveMutex cs_warnings;
static std::string strMiscWarning GUARDED_BY(cs_warnings);
static bool fLargeWorkForkFound GUARDED_BY(cs_warnings) = false;
static bool fLargeWorkInvalidChainFound GUARDED_BY(cs_warnings) = false;
std::string strMintWarning;

void SetMiscWarning(const std::string& strWarning)
{
    LOCK(cs_warnings);
    strMiscWarning = strWarning;
}

void SetfLargeWorkForkFound(bool flag)
{
    LOCK(cs_warnings);
    fLargeWorkForkFound = flag;
}

bool GetfLargeWorkForkFound()
{
    LOCK(cs_warnings);
    return fLargeWorkForkFound;
}

void SetfLargeWorkInvalidChainFound(bool flag)
{
    LOCK(cs_warnings);
    fLargeWorkInvalidChainFound = flag;
}

std::string GetWarnings(const std::string& strFor)
{
    int nPriority = 0;
    std::string strStatusBar;
    std::string strGUI;
    const std::string uiAlertSeperator = "<hr />";

    bool fCheckpointIsTooOld = CheckpointsSync::IsSyncCheckpointTooOld(60 * 60 * 24 * 10);
    LOCK(cs_warnings);

    if (!CLIENT_VERSION_IS_RELEASE) {
        strStatusBar = "This is a pre-release test build - use at your own risk - do not use for mining or merchant applications";
        strGUI = _("This is a pre-release test build - use at your own risk - do not use for mining or merchant applications").translated;
    }

    // ppcoin: wallet lock warning for minting
    if (strMintWarning != "")
    {
        strStatusBar = strMintWarning;
        strGUI = (strGUI.empty() ? "" : uiAlertSeperator) + strMintWarning;
    }

    // ppcoin: should not enter safe mode for longer invalid chain
    //         if sync-checkpoint is too old do not enter safe mode
    if (fCheckpointIsTooOld) {
        nPriority = 100;
        strStatusBar = "WARNING: Checkpoint is too old. Wait for block chain to download, or notify developers of the issue.";
        strGUI = (strGUI.empty() ? "" : uiAlertSeperator) + "WARNING: Checkpoint is too old. Wait for block chain to download, or notify developers of the issue.";
    }

    // Misc warnings like out of disk space and clock is wrong
    if (strMiscWarning != "")
    {
        nPriority = 1000;
        strStatusBar = strMiscWarning;
        strGUI += (strGUI.empty() ? "" : uiAlertSeperator) + strMiscWarning;
    }

    if (fLargeWorkForkFound)
    {
        nPriority = 2000;
        strStatusBar = "Warning: The network does not appear to fully agree! Some miners appear to be experiencing issues.";
        strGUI += (strGUI.empty() ? "" : uiAlertSeperator) + _("Warning: The network does not appear to fully agree! Some miners appear to be experiencing issues.").translated;
    }
    else if (fLargeWorkInvalidChainFound)
    {
        nPriority = 2000;
        strStatusBar = "Warning: We do not appear to fully agree with our peers! You may need to upgrade, or other nodes may need to upgrade.";
        strGUI += (strGUI.empty() ? "" : uiAlertSeperator) + _("Warning: We do not appear to fully agree with our peers! You may need to upgrade, or other nodes may need to upgrade.").translated;
    }

    // ppcoin: if detected invalid checkpoint enter safe mode
    if (CheckpointsSync::hashInvalidCheckpoint != uint256())
    {
        nPriority = 3000;
        strStatusBar = "WARNING: Invalid checkpoint found! Displayed transactions may not be correct! You may need to upgrade, or notify developers of the issue.";
        strGUI += (strGUI.empty() ? "" : uiAlertSeperator) + "WARNING: Invalid checkpoint found! Displayed transactions may not be correct! You may need to upgrade, or notify developers of the issue.";
    }

    //emcTODO strRPC safemode was removed. Re-add it again?
//    // Alerts
//    {
//        LOCK(cs_mapAlerts);
//        for (const auto& item : mapAlerts)
//        {
//            const CAlert& alert = item.second;
//            if (alert.AppliesToMe() && alert.nPriority > nPriority)
//            {
//                nPriority = alert.nPriority;
//                strStatusBar = strGUI = alert.strStatusBar;
//                if (nPriority > 1000)
//                    strRPC = strStatusBar;  // ppcoin: safe mode for high alert
//            }
//        }
//    }

    if (strFor == "gui")
        return strGUI;
    else if (strFor == "statusbar")
        return strStatusBar;
    assert(!"GetWarnings(): invalid parameter");
    return "error";
}
