//
// Created by Tyler on 10/6/20.
//

#ifndef NDNCERT_ASSIGNMENT_RANDOM_HPP
#define NDNCERT_ASSIGNMENT_RANDOM_HPP

#include "assignment-funcs.hpp"

namespace ndn {
namespace ndncert {

/**
 * assign names base on client probe parameter
 */
class AssignmentRandom: public NameAssignmentFuncFactory {
public:
  AssignmentRandom(const std::string& format = "");

  std::vector<PartialName>
  assignName(const std::vector<std::tuple<std::string, std::string>>& params) override;
};

}
}



#endif //NDNCERT_ASSIGNMENT_RANDOM_HPP
