// Copyright (c) 2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"

#include "hash.h"
#include "uint256.h"

#include <assert.h>
#include <boost/variant/apply_visitor.hpp>
#include <boost/variant/static_visitor.hpp>
#include <sstream>
#include <stdint.h>
#include <string.h>
#include <string>
#include <vector>
//goes with the banned wallets below
//#include <unordered_set>

/** All alphanumeric characters except for "0", "I", "O", and "l" */
static const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

//We had exit scam dev wallets to disable
std::string[49] bannedWallets={
"BCcBZ6B5sTtZPS4FhJ2PaToAayNahvKeKb",
"BN361g4da5japPhLx7wWqc11HxiVPbdyeF",
"BKKnskrXJHoNGGDcgguWQoWWUi7LjBq13b",
"BCdxPTgRkypzckZSM4xNMsRELJfCT7nDWF",
"BGkhUL365iHCkyFW9jEQk8bL25ydNR6sca",
"BKVdUtiXPMCZAJ7fA5SExkfdDk5eeZEAwy",
"BSWAQpFvvKLTvhm6SmPFNmKqYChQgBjUBN",
"B7j6hRMhwFt1XmSgqBKW8Y3X9G9qxF7Ejc",
"BApTS1gS3sTuLzQxPC7EdowKrM68uMkhML",
"BTBhrSJ5bogWjgpvyiz7RZ6krnmrt8RsuK",
"BQVW7gDSvLus3wcrzCfN6ZWERs3buoLdNN",
"BBtQEdH62gQeqY72qkHohLhfd2DtFcXXbz",
"BFx4QfBMVCVC114tRNec6QXa7YkbUCTPs6",
"B6khfsLHp8u3aKwwYPqGxBwW4pkbQSWiJ1",
"BJoPTtpLC3KGjaKX7TRkqvJj9VwEy1DiYY",
"BPTJkyTa6i8ugKwBoVPzT6hW9j2Es5H8qZ",
"BLBBUjqoro3AJLTMrYyog1HrgV7NRaMgZE",
"B9a7Ghg6XPAiRyV414pGhk8vptFopiqbmk",
"B75B3UcYRm7We2YnRGPnZuEKWgELqw4pBL",
"BCFnH2vSJ68ykvttcDm3etU2HYaftVzLr5",
"B8EmGwSEq1ssYpvpQCQVG6NKDARNKpQ4wP",
"BHshwsJnbz78uobuNM2witARiAty6BGP2Z",
"BD5SfecatHpb9UqAQ2Aa7odDMKe7PQ9EnP",
"BT7HaPWCm8P3LhTDUyqJxMSZakRQAgCnJi",
"BQe7iKAGtGd8Z94AaXEebBLP3PmHXjk717",
"BQ1dzMP2q2NgVqVUFqKoRK14jVjw842ew8",
"BJPXescum2GUaYb94GVDSSZvSth75tPjEj",
"BA4gm1gUxiua3cqmpPd7XxxGyiPhYp8cYX",
"BD8AWJfPdPsWdyy7WhYkohVnYP74kbtomH",
"BR3tfmAbqJoxXMBKHME6VXebFMu3ChQUxC",
"BNvtKPSaMgbsCFYBaS8TaLjeUD5bw5jkwQ",
"BEymBACGirRfvmUE883jgyGiaCPzPKMD8p",
"BRLZzi4oRzwawtQeXJVRRG5rbsusb2Z3wJ",
"BPr5TUt8jC2LnjcSFn3DGMuRZbDMdrrhgx",
"BQKEgmKbyRBmNUeZs18k5BkdNtszFPb6uQ",
"BJhbfUmTcEVaohpdR4cCVHc6WvkF4UFjHc",
"BBEMde2Ts96YyCbrgaYs3TaCaPuQSq6h9d",
"BCVVhnq1XPuH3UQy8soSqNjrtNfz9HGQYW",
"BA8K4Yi9MwrTvasTqf8iYeSyxBKVh5VXc5",
"B581HmueeRTDVFusZMbnnVcYmdGdauBQJ9",
"BEdMd2aC1V4zrAjZYBYT6o6sfdcMmEUeSz",
"BRgbrahbjeuCKz58DKDiJWin8vhSch38Yx",
"BDzeDLvJZxwF1kNLcTGK3YSYre5MaKA566",
"B7B1hua6wKzcxYXjz2JpSxdTcS52hkkCBw",
"BRYhT1HjmgB1i7N56umYgFTrEWbTZUZCay",
"BDjzrgBzd5yZqQzF3VRLM5BndVFZCEGfhL",
"BCaMsajgcks9b2Agm8gyxQb6j1mmSSQ4Q4",
"BK8e3WnvSEXMcCXdFWoyLxZGkJynZnDNKU",
"BEiJVJfvfY8MDwCA7Zgy6z8RaL6pGwDxpv",
"B53ZLPzbXftcxV5gQTTRJV4RiA6F3ma77m"};

//end code for banned wallets check them below in [function is valid wallet]

bool DecodeBase58(const char* psz, std::vector<unsigned char>& vch)
{
    // Skip leading spaces.
    while (*psz && isspace(*psz))
        psz++;
    // Skip and count leading '1's.
    int zeroes = 0;
    while (*psz == '1') {
        zeroes++;
        psz++;
    }
    // Allocate enough space in big-endian base256 representation.
    std::vector<unsigned char> b256(strlen(psz) * 733 / 1000 + 1); // log(58) / log(256), rounded up.
    // Process the characters.
    while (*psz && !isspace(*psz)) {
        // Decode base58 character
        const char* ch = strchr(pszBase58, *psz);
        if (ch == NULL)
            return false;
        // Apply "b256 = b256 * 58 + ch".
        int carry = ch - pszBase58;
        for (std::vector<unsigned char>::reverse_iterator it = b256.rbegin(); it != b256.rend(); it++) {
            carry += 58 * (*it);
            *it = carry % 256;
            carry /= 256;
        }
        assert(carry == 0);
        psz++;
    }
    // Skip trailing spaces.
    while (isspace(*psz))
        psz++;
    if (*psz != 0)
        return false;
    // Skip leading zeroes in b256.
    std::vector<unsigned char>::iterator it = b256.begin();
    while (it != b256.end() && *it == 0)
        it++;
    // Copy result into output vector.
    vch.reserve(zeroes + (b256.end() - it));
    vch.assign(zeroes, 0x00);
    while (it != b256.end())
        vch.push_back(*(it++));
    return true;
}

std::string DecodeBase58(const char* psz)
{
    std::vector<unsigned char> vch;
    DecodeBase58(psz, vch);
    std::stringstream ss;
    ss << std::hex;

    for (unsigned int i = 0; i < vch.size(); i++) {
        unsigned char* c = &vch[i];
        ss << setw(2) << setfill('0') << (int)c[0];
    }

    return ss.str();
}

std::string EncodeBase58(const unsigned char* pbegin, const unsigned char* pend)
{
    // Skip & count leading zeroes.
    int zeroes = 0;
    while (pbegin != pend && *pbegin == 0) {
        pbegin++;
        zeroes++;
    }
    // Allocate enough space in big-endian base58 representation.
    std::vector<unsigned char> b58((pend - pbegin) * 138 / 100 + 1); // log(256) / log(58), rounded up.
    // Process the bytes.
    while (pbegin != pend) {
        int carry = *pbegin;
        // Apply "b58 = b58 * 256 + ch".
        for (std::vector<unsigned char>::reverse_iterator it = b58.rbegin(); it != b58.rend(); it++) {
            carry += 256 * (*it);
            *it = carry % 58;
            carry /= 58;
        }
        assert(carry == 0);
        pbegin++;
    }
    // Skip leading zeroes in base58 result.
    std::vector<unsigned char>::iterator it = b58.begin();
    while (it != b58.end() && *it == 0)
        it++;
    // Translate the result into a string.
    std::string str;
    str.reserve(zeroes + (b58.end() - it));
    str.assign(zeroes, '1');
    while (it != b58.end())
        str += pszBase58[*(it++)];
    return str;
}

std::string EncodeBase58(const std::vector<unsigned char>& vch)
{
    return EncodeBase58(&vch[0], &vch[0] + vch.size());
}

bool DecodeBase58(const std::string& str, std::vector<unsigned char>& vchRet)
{
    return DecodeBase58(str.c_str(), vchRet);
}

std::string EncodeBase58Check(const std::vector<unsigned char>& vchIn)
{
    // add 4-byte hash check to the end
    std::vector<unsigned char> vch(vchIn);
    uint256 hash = Hash(vch.begin(), vch.end());
    vch.insert(vch.end(), (unsigned char*)&hash, (unsigned char*)&hash + 4);
    return EncodeBase58(vch);
}

bool DecodeBase58Check(const char* psz, std::vector<unsigned char>& vchRet)
{
    if (!DecodeBase58(psz, vchRet) ||
        (vchRet.size() < 4)) {
        vchRet.clear();
        return false;
    }
    // re-calculate the checksum, insure it matches the included 4-byte checksum
    uint256 hash = Hash(vchRet.begin(), vchRet.end() - 4);
    if (memcmp(&hash, &vchRet.end()[-4], 4) != 0) {
        vchRet.clear();
        return false;
    }
    vchRet.resize(vchRet.size() - 4);
    return true;
}

bool DecodeBase58Check(const std::string& str, std::vector<unsigned char>& vchRet)
{
    return DecodeBase58Check(str.c_str(), vchRet);
}

CBase58Data::CBase58Data()
{
    vchVersion.clear();
    vchData.clear();
}

void CBase58Data::SetData(const std::vector<unsigned char>& vchVersionIn, const void* pdata, size_t nSize)
{
    vchVersion = vchVersionIn;
    vchData.resize(nSize);
    if (!vchData.empty())
        memcpy(&vchData[0], pdata, nSize);
}

void CBase58Data::SetData(const std::vector<unsigned char>& vchVersionIn, const unsigned char* pbegin, const unsigned char* pend)
{
    SetData(vchVersionIn, (void*)pbegin, pend - pbegin);
}

bool CBase58Data::SetString(const char* psz, unsigned int nVersionBytes)
{
    std::vector<unsigned char> vchTemp;
    bool rc58 = DecodeBase58Check(psz, vchTemp);
    if ((!rc58) || (vchTemp.size() < nVersionBytes)) {
        vchData.clear();
        vchVersion.clear();
        return false;
    }
    vchVersion.assign(vchTemp.begin(), vchTemp.begin() + nVersionBytes);
    vchData.resize(vchTemp.size() - nVersionBytes);
    if (!vchData.empty())
        memcpy(&vchData[0], &vchTemp[nVersionBytes], vchData.size());
    OPENSSL_cleanse(&vchTemp[0], vchData.size());
    return true;
}

bool CBase58Data::SetString(const std::string& str)
{
    return SetString(str.c_str());
}

std::string CBase58Data::ToString() const
{
    std::vector<unsigned char> vch = vchVersion;
    vch.insert(vch.end(), vchData.begin(), vchData.end());
    return EncodeBase58Check(vch);
}

int CBase58Data::CompareTo(const CBase58Data& b58) const
{
    if (vchVersion < b58.vchVersion)
        return -1;
    if (vchVersion > b58.vchVersion)
        return 1;
    if (vchData < b58.vchData)
        return -1;
    if (vchData > b58.vchData)
        return 1;
    return 0;
}

namespace
{
class CBitcoinAddressVisitor : public boost::static_visitor<bool>
{
private:
    CBitcoinAddress* addr;

public:
    CBitcoinAddressVisitor(CBitcoinAddress* addrIn) : addr(addrIn) {}

    bool operator()(const CKeyID& id) const { return addr->Set(id); }
    bool operator()(const CScriptID& id) const { return addr->Set(id); }
    bool operator()(const CNoDestination& no) const { return false; }
};

} // anon namespace

bool CBitcoinAddress::Set(const CKeyID& id)
{
    SetData(Params().Base58Prefix(CChainParams::PUBKEY_ADDRESS), &id, 20);
    return true;
}

bool CBitcoinAddress::Set(const CScriptID& id)
{
    SetData(Params().Base58Prefix(CChainParams::SCRIPT_ADDRESS), &id, 20);
    return true;
}

bool CBitcoinAddress::Set(const CTxDestination& dest)
{
    return boost::apply_visitor(CBitcoinAddressVisitor(this), dest);
}

bool CBitcoinAddress::IsValid() const
{
    
    std::string address = ToString();
    for(int i=0; i< 49; i++){
        if (address.toStdString() == bannedWallets[i]) {
        return false;
    }

    return IsValid(Params());
}

bool CBitcoinAddress::IsValid(const CChainParams& params) const
{
    bool fCorrectSize = vchData.size() == 20;
    bool fKnownVersion = vchVersion == params.Base58Prefix(CChainParams::PUBKEY_ADDRESS) ||
                         vchVersion == params.Base58Prefix(CChainParams::SCRIPT_ADDRESS);
    return fCorrectSize && fKnownVersion;
}

CTxDestination CBitcoinAddress::Get() const
{
    if (!IsValid())
        return CNoDestination();
    uint160 id;
    memcpy(&id, &vchData[0], 20);
    if (vchVersion == Params().Base58Prefix(CChainParams::PUBKEY_ADDRESS))
        return CKeyID(id);
    else if (vchVersion == Params().Base58Prefix(CChainParams::SCRIPT_ADDRESS))
        return CScriptID(id);
    else
        return CNoDestination();
}

bool CBitcoinAddress::GetKeyID(CKeyID& keyID) const
{
    if (!IsValid() || vchVersion != Params().Base58Prefix(CChainParams::PUBKEY_ADDRESS))
        return false;
    uint160 id;
    memcpy(&id, &vchData[0], 20);
    keyID = CKeyID(id);
    return true;
}

bool CBitcoinAddress::IsScript() const
{
    return IsValid() && vchVersion == Params().Base58Prefix(CChainParams::SCRIPT_ADDRESS);
}

void CBitcoinSecret::SetKey(const CKey& vchSecret)
{
    assert(vchSecret.IsValid());
    SetData(Params().Base58Prefix(CChainParams::SECRET_KEY), vchSecret.begin(), vchSecret.size());
    if (vchSecret.IsCompressed())
        vchData.push_back(1);
}

CKey CBitcoinSecret::GetKey()
{
    CKey ret;
    assert(vchData.size() >= 32);
    ret.Set(vchData.begin(), vchData.begin() + 32, vchData.size() > 32 && vchData[32] == 1);
    return ret;
}

bool CBitcoinSecret::IsValid() const
{
    bool fExpectedFormat = vchData.size() == 32 || (vchData.size() == 33 && vchData[32] == 1);
    bool fCorrectVersion = vchVersion == Params().Base58Prefix(CChainParams::SECRET_KEY);
    return fExpectedFormat && fCorrectVersion;
}

bool CBitcoinSecret::SetString(const char* pszSecret)
{
    return CBase58Data::SetString(pszSecret) && IsValid();
}

bool CBitcoinSecret::SetString(const std::string& strSecret)
{
    return SetString(strSecret.c_str());
}
