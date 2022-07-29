/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2021, Regents of the University of California.
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

#ifndef NDNCERT_CHALLENGE_VC_HPP
#define NDNCERT_CHALLENGE_VC_HPP

#include "challenge-module.hpp"

namespace ndncert {

/**
 * @brief Provide VC based challenge
 *
 * @sa https://github.com/named-data/ndncert/wiki/NDN-Certificate-Management-Protocol
 *
 * The main process of this challenge module is:
 *   1. End entity provides empty string. The first POLL is only for selection.
 *   2. The challenge module will generate a PIN code in ChallengeDefinedField.
 *   3. End entity provides the verification code from some way to challenge module.
 *
 * There are four specific status defined in this challenge:
 *   NEED_CODE: When selection is made.
 *   WRONG_CODE: Get wrong verification code but still with secret lifetime and max retry times.
 *
 * Failure info when application fails:
 *   FAILURE_TIMEOUT: When secret is out-dated.
 *   FAILURE_MAXRETRY: When requester tries too many times.
 */
class ChallengeVC : public ChallengeModule
{
public:
  ChallengeVC(const std::string& configPath = "", 
              const std::string& requestProofScriptPath = "ndncert-vc-challenge-server", 
              const std::string& presentProofScriptPath = "ndncert-vc-challenge-client");

  // For CA
  std::tuple<ErrorCode, std::string>
  handleChallengeRequest(const Block& params, ca::RequestState& request) override;

  // For Client
  std::multimap<std::string, std::string>
  getRequestedParameterList(Status status, const std::string& challengeStatus) override;

  Block
  genChallengeRequestTLV(Status status, const std::string& challengeStatus,
                         const std::multimap<std::string, std::string>& params) override;

  // challenge status
  
  // parameters
  static const std::string PARAMETER_KEY_DID;

NDNCERT_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  void
  removeWhitespace(std::string& str);

  void 
  parseConfigFile();

  void
  sendProofRequest(const std::string& connectionDid);

NDNCERT_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  std::string m_configFile;
  std::string m_presentationRequest;
  std::string m_ariesAdminEndpoint;

private:
  std::string m_requestProofScript;
  std::string m_presentProofScript;
};

} // namespace ndncert

#endif // NDNCERT_CHALLENGE_VC_HPP
