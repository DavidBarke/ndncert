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

#include "challenge-vc.hpp"

#include <ndn-cxx/util/random.hpp>

namespace ndncert {

NDN_LOG_INIT(ndncert.challenge.vc);
NDNCERT_REGISTER_CHALLENGE(ChallengeVC, "vc_indy");

const std::string ChallengeVC::NEED_VC = "need-vc";

ChallengeVC::ChallengeVC(const std::string& configPath)
  : ChallengeModule("VC_Indy", 1, time::seconds(60))
{
  if (configPath.empty()) {
    m_configFile = std::string(NDNCERT_SYSCONFDIR) + "/ndncert/challenge-vc-indy.conf";
  }
  else {
    m_configFile = configPath;
  }
}

void
ChallengeVC::parseConfigFile()
{
  JsonSection config;
  try {
    boost::property_tree::read_json(m_configFile, config);
  }
  catch (const boost::property_tree::file_parser_error& error) {
    NDN_THROW(std::runtime_error("Failed to parse configuration file " + m_configFile + ": " +
                                 error.message() + " on line " + std::to_string(error.line())));
  }

  if (config.begin() == config.end()) {
    NDN_THROW(std::runtime_error("Error processing configuration file: " + m_configFile + " no data"));
  }

  m_trustAnchors.clear();
  auto anchorList = config.get_child("anchor-list");
  auto it = anchorList.begin();
  for (; it != anchorList.end(); it++) {
    std::istringstream ss(it->second.get("certificate", ""));
    auto cert = ndn::io::load<Certificate>(ss);
    if (cert == nullptr) {
      NDN_LOG_ERROR("Cannot load the certificate from config file");
      continue;
    }
    m_trustAnchors.push_back(*cert);
  }
}

// For CA
std::tuple<ErrorCode, std::string>
ChallengeVC::handleChallengeRequest(const Block& params, ca::RequestState& request)
{
  params.parse();
  auto currentTime = time::system_clock::now();
  if (request.status == Status::BEFORE_CHALLENGE) {
    NDN_LOG_TRACE("Challenge Interest arrives. Init the challenge");
    // for the first time, init the challenge
    std::string secretCode = generateSecretCode();
    JsonSection secretJson;
    secretJson.add(PARAMETER_KEY_CODE, secretCode);
    NDN_LOG_TRACE("Secret for request " << ndn::toHex(request.requestId)
                  << " : " << secretCode);
    return returnWithNewChallengeStatus(request, NEED_CODE, std::move(secretJson), m_maxAttemptTimes,
                                        m_secretLifetime);
  }
  if (request.challengeState) {
    if (request.challengeState->challengeStatus == NEED_CODE ||
        request.challengeState->challengeStatus == WRONG_CODE) {
      NDN_LOG_TRACE("Challenge Interest arrives. Challenge Status: " << request.challengeState->challengeStatus);
      // the incoming interest should bring the pin code
      std::string givenCode = readString(params.get(tlv::ParameterValue));
      auto secret = request.challengeState->secrets;
      if (currentTime - request.challengeState->timestamp >= m_secretLifetime) {
        return returnWithError(request, ErrorCode::OUT_OF_TIME, "Secret expired.");
      }
      if (givenCode == secret.get<std::string>(PARAMETER_KEY_CODE)) {
        NDN_LOG_TRACE("Correct PIN code. Challenge succeeded.");
        return returnWithSuccess(request);
      }
      // check rest attempt times
      if (request.challengeState->remainingTries > 1) {
        auto remainTime = m_secretLifetime - (currentTime - request.challengeState->timestamp);
        NDN_LOG_TRACE("Wrong PIN code provided. Remaining Tries - 1.");
        return returnWithNewChallengeStatus(request, WRONG_CODE, std::move(secret),
                                            request.challengeState->remainingTries - 1,
                                            time::duration_cast<time::seconds>(remainTime));
      }
      else {
        // run out times
        NDN_LOG_TRACE("Wrong PIN code provided. Ran out tires. Challenge failed.");
        return returnWithError(request, ErrorCode::OUT_OF_TRIES, "Ran out tires.");
      }
    }
  }
  return returnWithError(request, ErrorCode::INVALID_PARAMETER, "Unexpected status or challenge status");
}

// For Client
std::multimap<std::string, std::string>
ChallengeVC::getRequestedParameterList(Status status, const std::string& challengeStatus)
{
  std::multimap<std::string, std::string> result;
  if (status == Status::BEFORE_CHALLENGE) {
    // do nothing
  }
  else if (status == Status::CHALLENGE && challengeStatus == NEED_CODE) {
    result.emplace(PARAMETER_KEY_CODE, "Please input your PIN code");
  }
  else if (status == Status::CHALLENGE && challengeStatus == WRONG_CODE) {
    result.emplace(PARAMETER_KEY_CODE, "Incorrect PIN code, please try again");
  }
  else {
    NDN_THROW(std::runtime_error("Unexpected status or challenge status."));
  }
  return result;
}

Block
ChallengeVC::genChallengeRequestTLV(Status status, const std::string& challengeStatus,
                                     const std::multimap<std::string, std::string>& params)
{
  Block request(tlv::EncryptedPayload);
  if (status == Status::BEFORE_CHALLENGE) {
    request.push_back(ndn::makeStringBlock(tlv::SelectedChallenge, CHALLENGE_TYPE));
  }
  else if (status == Status::CHALLENGE && (challengeStatus == NEED_CODE || challengeStatus == WRONG_CODE)) {
    if (params.size() != 1 || params.find(PARAMETER_KEY_CODE) == params.end()) {
      NDN_THROW(std::runtime_error("Wrong parameter provided."));
    }
    request.push_back(ndn::makeStringBlock(tlv::SelectedChallenge, CHALLENGE_TYPE));
    request.push_back(ndn::makeStringBlock(tlv::ParameterKey, PARAMETER_KEY_CODE));
    request.push_back(ndn::makeStringBlock(tlv::ParameterValue, params.find(PARAMETER_KEY_CODE)->second));
  }
  else {
    NDN_THROW(std::runtime_error("Unexpected status or challenge status."));
  }
  request.encode();
  return request;
}

} // namespace ndncert
