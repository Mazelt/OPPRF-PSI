//
// \file psi_analytics_example.cpp
// \author Oleksandr Tkachenko
// \email tkachenko@encrypto.cs.tu-darmstadt.de
// \organization Cryptography and Privacy Engineering Group (ENCRYPTO)
// \TU Darmstadt, Computer Science department
//
// \copyright The MIT License. Copyright Oleksandr Tkachenko
//

#include <cassert>
#include <iostream>

#include <boost/program_options.hpp>

#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/parse_options.h>
#include "abycore/aby/abyparty.h"

#include "common/psi_analytics.h"
#include "common/psi_analytics_context.h"

auto read_test_options(int32_t argcp, char **argvp) {
  namespace po = boost::program_options;
  ENCRYPTO::PsiAnalyticsContext context;
  po::options_description allowed("Allowed options");
  std::string type;
  // clang-format off
  allowed.add_options()("help,h", "produce this message")
  ("role,r",         po::value<decltype(context.role)>(&context.role)->required(),                                  "Role of the node")
  ("neles,n",        po::value<decltype(context.neles)>(&context.neles)->default_value(1000u),                      "Number of my elements")
  ("bit-length,b",   po::value<decltype(context.bitlen)>(&context.bitlen)->default_value(61u),                      "Bit-length of the elements")
  ("epsilon,e",      po::value<decltype(context.epsilon)>(&context.epsilon)->default_value(2.4f),                   "Epsilon, a table size multiplier")
  ("address,a",      po::value<decltype(context.address)>(&context.address)->default_value("127.0.0.1"),            "IP address of the server")
  ("port,p",         po::value<decltype(context.port)>(&context.port)->default_value(7777),                         "Port of the server")
  ("threads,t",      po::value<decltype(context.nthreads)>(&context.nthreads)->default_value(1),                    "Number of threads")
  ("others-neles,o", po::value<decltype(context.notherpartyselems)>(&context.notherpartyselems)->default_value(0u), "Number of other party's elements")
  ("threshold,c",    po::value<decltype(context.threshold)>(&context.threshold)->default_value(0u),                 "Show PSI size if it is > threshold")
  ("nmegabins,m",    po::value<decltype(context.nmegabins)>(&context.nmegabins)->default_value(1u),                 "Number of mega bins")
  ("polysize,s",     po::value<decltype(context.polynomialsize)>(&context.polynomialsize)->default_value(0u),       "Size of the polynomial(s), default: neles")
  ("functions,f",    po::value<decltype(context.nfuns)>(&context.nfuns)->default_value(2u),                         "Number of hash functions in hash tables")
  ("payload_a_bitlen", po::value<decltype(context.payload_bitlen)>(&context.payload_bitlen)->default_value(2u),  "Bit-length of payload A input")
  ("type,y",         po::value<std::string>(&type)->default_value("None"),                                          "Function type {None, Threshold, Sum, SumIfGtThreshold, PayloadASum, PayloadASumGT, PayloadABSum, PayloadABSumGT, PayloadABMulSum, PayloadABMulSumGT}")  // clang-format on
  ("overlap"        ,po::value<decltype(context.overlap)>(&context.overlap)->default_value(100u),                   "items overlap.");

  po::variables_map vm;
  try {
    po::store(po::parse_command_line(argcp, argvp, allowed), vm);
    po::notify(vm);
  } catch (const boost::exception_detail::clone_impl<boost::exception_detail::error_info_injector<
               boost::program_options::required_option> > &e) {
    if (!vm.count("help")) {
      std::cout << e.what() << std::endl;
      std::cout << allowed << std::endl;
      exit(EXIT_FAILURE);
    }
  }

  if (vm.count("help")) {
    std::cout << allowed << "\n";
    exit(EXIT_SUCCESS);
  }

  if (type.compare("None") == 0) {
    context.analytics_type = ENCRYPTO::PsiAnalyticsContext::NONE;
  } else if (type.compare("Threshold") == 0) {
    context.analytics_type = ENCRYPTO::PsiAnalyticsContext::THRESHOLD;
  } else if (type.compare("Sum") == 0) {
    context.analytics_type = ENCRYPTO::PsiAnalyticsContext::SUM;
  } else if (type.compare("SumIfGtThreshold") == 0) {
    context.analytics_type = ENCRYPTO::PsiAnalyticsContext::SUM_IF_GT_THRESHOLD;
  } else if (type.compare("PayloadASum") == 0) {
    context.analytics_type = ENCRYPTO::PsiAnalyticsContext::PAYLOAD_A_SUM;
  } else if (type.compare("PayloadASumGT") == 0) {
    context.analytics_type = ENCRYPTO::PsiAnalyticsContext::PAYLOAD_A_SUM_GT;
  } else if (type.compare("PayloadABSum") == 0) {
    context.analytics_type = ENCRYPTO::PsiAnalyticsContext::PAYLOAD_AB_SUM;
  } else if (type.compare("PayloadABSumGT") == 0) {
    context.analytics_type = ENCRYPTO::PsiAnalyticsContext::PAYLOAD_AB_SUM_GT;
  } else if (type.compare("PayloadABMulSum") == 0) {
    context.analytics_type = ENCRYPTO::PsiAnalyticsContext::PAYLOAD_AB_MUL_SUM;
  } else if (type.compare("PayloadABMulSumGT") == 0) {
    context.analytics_type = ENCRYPTO::PsiAnalyticsContext::PAYLOAD_AB_MUL_SUM_GT;
  } else {
    std::string error_msg(std::string("Unknown function type: " + type));
    throw std::runtime_error(error_msg.c_str());
  }

  if (context.notherpartyselems == 0) {
    context.notherpartyselems = context.neles;
  }

  if (context.polynomialsize == 0) {
    context.polynomialsize = context.neles * context.nfuns;
  }
  context.polynomialbytelength = context.polynomialsize * sizeof(std::uint64_t);

  const std::size_t client_neles =
      context.role == CLIENT ? context.neles : context.notherpartyselems;
  context.nbins = client_neles * context.epsilon;

  return context;
}

int main(int argc, char **argv) {
  auto context = read_test_options(argc, argv);
  auto gen_bitlen = static_cast<std::size_t>(std::ceil(std::log2(context.neles))) + 3;
  auto offset = std::ceil((double(100- context.overlap)/100.0) * context.notherpartyselems) ;
  auto inputs = ENCRYPTO::GenerateSequentialElements(context.neles, offset);


  auto psi_type = context.analytics_type;

  bool payload_b_if = (psi_type == ENCRYPTO::PsiAnalyticsContext::PAYLOAD_AB_SUM ||
                       psi_type == ENCRYPTO::PsiAnalyticsContext::PAYLOAD_AB_SUM_GT ||
                       psi_type == ENCRYPTO::PsiAnalyticsContext::PAYLOAD_AB_MUL_SUM ||
                       psi_type == ENCRYPTO::PsiAnalyticsContext::PAYLOAD_AB_MUL_SUM_GT);
  bool payload_a_if = (payload_b_if || psi_type == ENCRYPTO::PsiAnalyticsContext::PAYLOAD_A_SUM ||
                       psi_type == ENCRYPTO::PsiAnalyticsContext::PAYLOAD_A_SUM_GT);

  std::vector<uint64_t> payload_a, payload_b;

  if (context.role == CLIENT && payload_a_if) {
    payload_a = ENCRYPTO::GenerateRandomPayload(context.neles, context.payload_bitlen, CLIENT);
  } else if (context.role == SERVER && payload_b_if) {
    payload_b = ENCRYPTO::GenerateRandomPayload(context.neles, context.payload_bitlen, SERVER);
  }
  auto out = ENCRYPTO::run_psi_analytics(inputs, context, payload_a, payload_b);

  std::cout << "PSI circuit successfully executed. Result: " << out << std::endl;
  PrintTimings(context);
  PrintComm(context);
  return EXIT_SUCCESS;
}
