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
#include <regex>

namespace ndncert {

NDN_LOG_INIT(ndncert.challenge.vc);
NDNCERT_REGISTER_CHALLENGE(ChallengeVC, "vc");

const std::string ChallengeVC::PARAMETER_KEY_DID = "did";
const std::string ChallengeVC::PARAMETER_KEY_PRESENTATION_ID = "presentation-id";
const std::string ChallengeVC::NEED_PRESENTATION_ID = "need-presentation-id";

ChallengeVC::ChallengeVC(const std::string& configPath, const std::string& sendPresentationScriptPath, const std::string& verifyPresentationScriptPath)
  : ChallengeModule("vc", 1, time::seconds(60)),
  m_sendPresentationScriptPath(sendPresentationScriptPath),
  m_verifyPresentationScriptPath(verifyPresentationScriptPath)
{
  if (configPath.empty()) {
    m_configFile = std::string(NDNCERT_SYSCONFDIR) + "/ndncert/challenge-vc.conf";
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
    std::string connection_did = readString(params.get(tlv::ParameterValue)); 
    std::string presentationId = sendPresentationRequest(connection_did);
    JsonSection secretJson;
    secretJson.add(PARAMETER_KEY_PRESENTATION_ID, presentationId);
    NDN_LOG_TRACE("Secret for request " << ndn::toHex(request.requestId) << " : " << presentationId);
    return returnWithNewChallengeStatus(request, NEED_PRESENTATION_ID, std::move(secretJson), m_maxAttemptTimes,
                                        m_secretLifetime);
  }
  if (request.challengeState && request.challengeState->challengeStatus == NEED_PRESENTATION_ID) {
    NDN_LOG_TRACE("Challenge Interest (Presentation ID) arrives. Check that verifiable credential has been presented");
    std::string givenPresentationId = readString(params.get(tlv::ParameterValue));
    auto secret = request.challengeState->secrets;
    if (givenPresentationId == secret.get<std::string>(PARAMETER_KEY_PRESENTATION_ID)) {
      NDN_LOG_TRACE("Correct Presentation ID. Check that presentation request has been fulfilled.");
      bool fulfilled = verifyPresentationRequest(givenPresentationId);
      if (fulfilled) {
        return returnWithSuccess(request);
      } else {
        return returnWithError(request, ErrorCode::INVALID_PARAMETER, "Cannot verify that presentation request has been fulfilled.");
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
  if (status == Status::BEFORE_CHALLENGE && challengeStatus.empty()) {
    result.emplace(PARAMETER_KEY_DID, "Please input your DID of your connection with the CA.");
  }
  else if (status == Status::CHALLENGE && challengeStatus == NEED_PRESENTATION_ID) {
    result.emplace(PARAMETER_KEY_PRESENTATION_ID, "Please input the presentation ID of the presentation request you fulfilled with the CA.");
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
  else if (status == Status::CHALLENGE && challengeStatus == NEED_PRESENTATION_ID) {
    if (params.size() != 1 || params.find(PARAMETER_KEY_PRESENTATION_ID) == params.end()) {
      NDN_THROW(std::runtime_error("Wrong parameter provided."));
    }
    request.push_back(ndn::makeStringBlock(tlv::SelectedChallenge, CHALLENGE_TYPE));
    request.push_back(ndn::makeStringBlock(tlv::ParameterKey, PARAMETER_KEY_PRESENTATION_ID));
    request.push_back(ndn::makeStringBlock(tlv::ParameterValue, params.find(PARAMETER_KEY_PRESENTATION_ID)->second));
  } 
  else {
    NDN_THROW(std::runtime_error("Unexpected status or challenge status."));
  }
  request.encode();
  return request;
}

std::string ChallengeVC::sendPresentationRequest(const std::string& connectionDid) {
  std::string presentationId;
  std::string command = m_sendPresentationScriptPath;
  command += " " + std::string("--connection_did") + " \"" + connectionDid + "\" "
                 + "--config_file" + " \"" + m_configFile + "\" "
                 + "--log" + " \"" + "DEBUG" + "\"";
  boost::process::ipstream stream;
  boost::process::child child(command, boost::process::std_out > stream);
  std::string line;
  while(child.running() && getline(stream, line)) {
    NDN_LOG_TRACE("<Python>: " + line);
    // Receive presentation_id message
    if (line.rfind("<msg>:presentation_id", 0) == 0) {
      std::regex r = std::regex("^<msg>:presentation_id:([\\w\\-]+)$");
      std::smatch m;
      std::regex_search(line, m, r);
      presentationId = std::string(m[1]);
    }
  }
  child.wait();
  if (child.exit_code() != 0) {
    NDN_LOG_TRACE("SendPresentationScript " + m_sendPresentationScriptPath + " fails.");
  }
  else {
    NDN_LOG_TRACE("SendPresentationScript " + m_sendPresentationScriptPath + " was executed succesfully with return value 0.");
  }
  return presentationId;
}

bool ChallengeVC::verifyPresentationRequest(const std::string& presentationId) {
  bool verified = false;
  std::string command = m_verifyPresentationScriptPath;
  command += " " + std::string("--presentation_id") + " \"" + presentationId + "\" "
                 + "--config_file" + " \"" + m_configFile + "\" "
                 + "--log" + " \"" + "DEBUG" + "\"";
  boost::process::ipstream stream;
  boost::process::child child(command, boost::process::std_out > stream);
  std::string line;
  while(child.running() && getline(stream, line)) {
    NDN_LOG_TRACE("<Python>: " + line);
    // Receive success message
    if (line.rfind("<msg>:verified", 0) == 0) {
      std::regex r = std::regex("^<msg>:verified:([\\w]+)$");
      std::smatch m;
      std::regex_search(line, m, r);
      verified = m[1] == "true";
      if (verified) {
        NDN_LOG_TRACE("Presentation request for presentation id " + presentationId + " verified.");
      }
      else {
        NDN_LOG_TRACE("Presentation request for presentation id " + presentationId + " could not be verified.");
      } 
    }
  }
  child.wait();
  if (child.exit_code() != 0) {
    NDN_LOG_TRACE("VerifyPresentationScript " + m_verifyPresentationScriptPath + " fails.");
  }
  else {
    NDN_LOG_TRACE("VerifyPresentationScript " + m_verifyPresentationScriptPath + " was executed succesfully with return value 0.");
  }
  return verified;
}

} // namespace ndncert
