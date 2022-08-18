/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2022, Regents of the University of California.
 *
 * This file is part of ndncert, a certificate management system based on NDN.
 *
 * ndncert is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.
 *
 * ndncert is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received copies of the GNU General Public License along with
 * ndncert, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndncert authors and contributors.
 */

#include "challenge/challenge-vc.hpp"

#include "tests/boost-test.hpp"
#include "tests/key-chain-fixture.hpp"

#include <fstream>

namespace ndncert::tests {

BOOST_FIXTURE_TEST_SUITE(TestChallengeVC, KeyChainFixture)

BOOST_AUTO_TEST_CASE(ChallengeType)
{
  ChallengeVC challenge;
  BOOST_CHECK_EQUAL(challenge.CHALLENGE_TYPE, "vc");
}

BOOST_AUTO_TEST_CASE(OnChallengeRequestWithDID)
{
    auto identity = m_keyChain.createIdentity(Name("/ndn/site1"));
    auto key = identity.getDefaultKey();
    auto cert = key.getDefaultCertificate();
    RequestId requestId = {{101}};
    ca::RequestState request;
    request.caPrefix = Name("/ndn/site1");
    request.requestId = requestId;
    request.requestType = RequestType::NEW;
    request.cert = cert;

    Block paramTLV = ndn::makeEmptyBlock(tlv::EncryptedPayload);
    paramTLV.push_back(ndn::makeStringBlock(tlv::ParameterKey, ChallengeVC::PARAMETER_KEY_DID));
    paramTLV.push_back(ndn::makeStringBlock(tlv::ParameterValue, "did"));

    ChallengeVC challenge(
        "./tests/unit-tests/config-files/config-challenge-vc", 
        "./tests/unit-tests/test-send-presentation-request.sh",
        "./tests/unit-tests/test-verify-presentation.sh"
    );
    challenge.handleChallengeRequest(paramTLV, request);

    BOOST_CHECK(request.status == Status::CHALLENGE);
    BOOST_CHECK_EQUAL(request.challengeState->challengeStatus, ChallengeVC::NEED_PRESENTATION_ID);
    // presentation_id is only different from "" if python script sends presentation_id of presentation exchange
    BOOST_CHECK(request.challengeState->secrets.get<std::string>(ChallengeVC::PARAMETER_KEY_PRESENTATION_ID) == "");
    BOOST_CHECK(request.challengeState->remainingTime.count() != 0);
    BOOST_CHECK(request.challengeState->remainingTries != 0);
    BOOST_CHECK_EQUAL(request.challengeType, "vc");

    std::string line = "";
    std::string delimiter = " ";
    std::ifstream sendFile("tmp.txt");
    if (sendFile.is_open()) {
        getline(sendFile, line);
        sendFile.close();
    }

    int end = line.find(delimiter);
    std::string connectionDid = line.substr(0, end);
    BOOST_CHECK_EQUAL(connectionDid, "did");
    line = line.substr(end + 1);

    end = line.find(delimiter);
    std::string configFile = line.substr(0, end);
    BOOST_CHECK_EQUAL(configFile, "./tests/unit-tests/config-files/config-challenge-vc");
    line = line.substr(end + 1);

    std::string log = line.substr(0, end);
    BOOST_CHECK_EQUAL(log, "DEBUG");
    std::remove("tmp.txt");
}

BOOST_AUTO_TEST_CASE(OnChallengeRequestWithPresentationId) 
{
    auto identity = m_keyChain.createIdentity(Name("/ndn/site1"));
    auto key = identity.getDefaultKey();
    auto cert = key.getDefaultCertificate();
    JsonSection secret;
    secret.put(ChallengeVC::PARAMETER_KEY_PRESENTATION_ID, "presentation-id");
    RequestId requestId = {{101}};
    ca::RequestState request;
    request.caPrefix = Name("/ndn/site1");
    request.requestId = requestId;
    request.requestType = RequestType::NEW;
    request.status = Status::CHALLENGE;
    request.cert = cert;
    request.challengeType = "vc";
    request.challengeState = ca::ChallengeState(
        ChallengeVC::NEED_PRESENTATION_ID, time::system_clock::now(), 1, time::seconds(3600), std::move(secret)
    );

    Block paramTLV = ndn::makeEmptyBlock(tlv::EncryptedPayload);
    paramTLV.push_back(ndn::makeStringBlock(tlv::ParameterKey, ChallengeVC::PARAMETER_KEY_PRESENTATION_ID));
    paramTLV.push_back(ndn::makeStringBlock(tlv::ParameterValue, "presentation-id"));

    ChallengeVC challenge(
        "./tests/unit-tests/config-files/config-challenge-vc", 
        "./tests/unit-tests/test-send-presentation-request.sh",
        "./tests/unit-tests/test-verify-presentation.sh"
    );
    challenge.handleChallengeRequest(paramTLV, request);

    // challenge is only successful if python script sends fulfilled message
    BOOST_CHECK(request.status == Status::FAILURE);
    BOOST_CHECK(!request.challengeState);

    std::string line = "";
    std::string delimiter = " ";
    std::ifstream checkFile("tmp.txt");
    if (checkFile.is_open()) {
        getline(checkFile, line);
        checkFile.close();
    }

    int end = line.find(delimiter);
    std::string presentationId = line.substr(0, end);
    BOOST_CHECK_EQUAL(presentationId, "presentation-id");
    line = line.substr(end + 1);

    end = line.find(delimiter);
    std::string configFile = line.substr(0, end);
    BOOST_CHECK_EQUAL(configFile, "./tests/unit-tests/config-files/config-challenge-vc");
    line = line.substr(end + 1);

    std::string log = line.substr(0, end);
    BOOST_CHECK_EQUAL(log, "DEBUG");
    std::remove("tmp.txt");
}

BOOST_AUTO_TEST_SUITE_END() // TestChallengeVC

} // namespace ndncert::tests