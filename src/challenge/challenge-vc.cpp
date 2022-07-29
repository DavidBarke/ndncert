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
#include <boost/process.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <iostream>

namespace ndncert {

NDN_LOG_INIT(ndncert.challenge.vc);
NDNCERT_REGISTER_CHALLENGE(ChallengeVC, "vc");

const std::string ChallengeVC::PARAMETER_KEY_DID = "did";

ChallengeVC::ChallengeVC(const std::string& configPath, const std::string& requestProofScriptPath, const std::string& presentProofScriptPath)
  : ChallengeModule("vc", 1, time::seconds(60)),
  m_requestProofScript(requestProofScriptPath),
  m_presentProofScript(presentProofScriptPath)
{
  if (configPath.empty()) {
    m_configFile = std::string(NDNCERT_SYSCONFDIR) + "/ndncert/challenge-vc.conf";
  }
  else {
    m_configFile = configPath;
  }
}

void 
ChallengeVC::removeWhitespace(std::string& str) {
  str.erase(std::remove(str.begin(), str.end(), ' '), str.end());
  str.erase(std::remove(str.begin(), str.end(), '\n'), str.end());
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

  JsonSection proof_request = config.get_child("presentation-request");
  std::stringstream ss;
  boost::property_tree::json_parser::write_json(ss, proof_request, false);
  std::string presentationRequest = ss.str();
  //removeWhitespace(presentationRequest);
  m_presentationRequest = presentationRequest;
  m_ariesAdminEndpoint = config.get_child("aries-admin-endpoint").data();
  std::cout << m_presentationRequest << std::endl;
  std::cout << m_ariesAdminEndpoint << std::endl;
}

// For CA
std::tuple<ErrorCode, std::string>
ChallengeVC::handleChallengeRequest(const Block& params, ca::RequestState& request)
{
  params.parse();
  if (m_presentationRequest.empty()) {
    parseConfigFile();
  }
  if (request.status == Status::BEFORE_CHALLENGE) {
    // for the first time, init the challenge
    NDN_LOG_TRACE("Challenge Interest arrives. Init the challenge");
    std::cout << "Init" << std::endl;
    std::string connection_did = readString(params.get(tlv::ParameterValue)); 
    std::cout << "connection_did: " << connection_did << std::endl;
    sendProofRequest(connection_did);
    return returnWithSuccess(request);
  }
  // if (request.challengeState) {
  //   if (request.challengeState->challengeStatus == NEED_CODE ||
  //       request.challengeState->challengeStatus == WRONG_CODE) {
  //     NDN_LOG_TRACE("Challenge Interest arrives. Challenge Status: " << request.challengeState->challengeStatus);
  //     // the incoming interest should bring the pin code
  //     std::string givenCode = readString(params.get(tlv::ParameterValue));
  //     auto secret = request.challengeState->secrets;
  //     if (currentTime - request.challengeState->timestamp >= m_secretLifetime) {
  //       return returnWithError(request, ErrorCode::OUT_OF_TIME, "Secret expired.");
  //     }
  //     if (givenCode == secret.get<std::string>(PARAMETER_KEY_CODE)) {
  //       NDN_LOG_TRACE("Correct PIN code. Challenge succeeded.");
  //       return returnWithSuccess(request);
  //     }
  //     // check rest attempt times
  //     if (request.challengeState->remainingTries > 1) {
  //       auto remainTime = m_secretLifetime - (currentTime - request.challengeState->timestamp);
  //       NDN_LOG_TRACE("Wrong PIN code provided. Remaining Tries - 1.");
  //       return returnWithNewChallengeStatus(request, WRONG_CODE, std::move(secret),
  //                                           request.challengeState->remainingTries - 1,
  //                                           time::duration_cast<time::seconds>(remainTime));
  //     }
  //     else {
  //       // run out times
  //       NDN_LOG_TRACE("Wrong PIN code provided. Ran out tires. Challenge failed.");
  //       return returnWithError(request, ErrorCode::OUT_OF_TRIES, "Ran out tires.");
  //     }
  //   }
  // }
  return returnWithError(request, ErrorCode::INVALID_PARAMETER, "Unexpected status or challenge status");
}

// For Client
std::multimap<std::string, std::string>
ChallengeVC::getRequestedParameterList(Status status, const std::string& challengeStatus)
{
  std::multimap<std::string, std::string> result;
  if (status == Status::BEFORE_CHALLENGE && challengeStatus.empty()) {
    result.emplace(PARAMETER_KEY_DID, "Please input your DID of your connection with the CA.");
  }
  else if (status == Status::CHALLENGE) {
    result.emplace(PARAMETER_KEY_DID, "Please input your DID of your connection with the CA.");
  }
  else if (status == Status::CHALLENGE) {
    result.emplace(PARAMETER_KEY_DID, "CA has no connection with you with the supplied DID, please try again.");
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
    if (params.size() != 1 || params.find(PARAMETER_KEY_DID) == params.end()) {
      NDN_THROW(std::runtime_error("Wrong parameter provided."));
    }
    request.push_back(ndn::makeStringBlock(tlv::SelectedChallenge, CHALLENGE_TYPE));
    request.push_back(ndn::makeStringBlock(tlv::ParameterKey, PARAMETER_KEY_DID));
    request.push_back(ndn::makeStringBlock(tlv::ParameterValue, params.find(PARAMETER_KEY_DID)->second));
  }
  else if (status == Status::CHALLENGE) {
    if (params.size() != 1 || params.find(PARAMETER_KEY_DID) == params.end()) {
      NDN_THROW(std::runtime_error("Wrong parameter provided."));
    }
    request.push_back(ndn::makeStringBlock(tlv::SelectedChallenge, CHALLENGE_TYPE));
    request.push_back(ndn::makeStringBlock(tlv::ParameterKey, PARAMETER_KEY_DID));
    request.push_back(ndn::makeStringBlock(tlv::ParameterValue, params.find(PARAMETER_KEY_DID)->second));
  } 
  else {
    NDN_THROW(std::runtime_error("Unexpected status or challenge status."));
  }
  request.encode();
  return request;
}

void ChallengeVC::sendProofRequest(const std::string& connectionDid) {
  std::string command = m_requestProofScript;
  command += " " + std::string("--connection_did") + " \"" + connectionDid + "\" "
                 + "--config_file" + " \"" + m_configFile + "\"";
  boost::process::ipstream stream;
  boost::process::child child(command, boost::process::std_out > stream);
  std::string line;
  while(child.running() && getline(stream, line)) {
    std::cout << "From Python: " << line << std::endl;
  }
  child.wait();
  if (child.exit_code() != 0) {
    NDN_LOG_TRACE("RequestProofScript " + m_requestProofScript + " fails.");
  }
  else {
    NDN_LOG_TRACE("RequestProofScript " + m_requestProofScript + " was executed succesfully with return value 0.");
  }
}

} // namespace ndncert
