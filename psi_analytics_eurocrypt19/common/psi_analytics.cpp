//
// \author Oleksandr Tkachenko
// \email tkachenko@encrypto.cs.tu-darmstadt.de
// \organization Cryptography and Privacy Engineering Group (ENCRYPTO)
// \TU Darmstadt, Computer Science department
//
// \copyright The MIT License. Copyright Oleksandr Tkachenko
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the Software
// is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
// INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR
// A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
// OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include "psi_analytics.h"

#include "ENCRYPTO_utils/connection.h"
#include "ENCRYPTO_utils/socket.h"
#include "abycore/sharing/arithsharing.h"
#include "abycore/sharing/boolsharing.h"
#include "abycore/sharing/sharing.h"

#include "ots/ots.h"
#include "polynomials/Poly.h"

#include "HashingTables/cuckoo_hashing/cuckoo_hashing.h"
#include "HashingTables/simple_hashing/simple_hashing.h"
#include "psi_analytics_context.h"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <random>
#include <ratio>
#include <unordered_set>

namespace ENCRYPTO {

using share_ptr = std::shared_ptr<share>;

using milliseconds_ratio = std::ratio<1, 1000>;
using duration_millis = std::chrono::duration<double, milliseconds_ratio>;

uint64_t run_psi_analytics(const std::vector<std::uint64_t> &inputs, PsiAnalyticsContext &context) {
  std::vector<std::uint64_t> payload_a_dummy;
  return run_psi_analytics(inputs, context, payload_a_dummy);
}

uint64_t run_psi_analytics(const std::vector<std::uint64_t> &inputs, PsiAnalyticsContext &context,
                           const std::vector<std::uint64_t> &payload_input_a) {
  // establish network connection
  std::unique_ptr<CSocket> sock =
      EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));
  sock->Close();
  const auto clock_time_total_start = std::chrono::system_clock::now();

  // create hash tables from the elements
  // and create and send hints.
  std::vector<uint64_t> bins;

  std::vector<uint64_t> payload_a_index;
  if (context.role == CLIENT) {
    std::vector<std::pair<uint64_t, uint64_t>> bins_index;
    bins_index = OpprgPsiClient(inputs, context);
    if (context.analytics_type == PsiAnalyticsContext::PAYLOAD_A_SUM ||
        context.analytics_type == PsiAnalyticsContext::PAYLOAD_A_SUM_GT) {
      payload_a_index.reserve(bins_index.size());
      for (auto i = 0ull; i < bins_index.size(); ++i) {
        bins.push_back(bins_index[i].first);
        payload_a_index.push_back(bins_index[i].second);
      }
    } else {
      for (auto i = 0ull; i < bins_index.size(); ++i) {
        bins.push_back(bins_index[i].first);
      }
    }

  } else {
    bins = OpprgPsiServer(inputs, context);
  }

  // instantiate ABY
  ABYParty party(static_cast<e_role>(context.role), context.address, context.port, LT, 64,
                 context.nthreads);
  party.ConnectAndBaseOTs();
  auto bc = dynamic_cast<BooleanCircuit *>(
      party.GetSharings().at(S_BOOL)->GetCircuitBuildRoutine());  // GMW circuit
  // does moving these initiations to the if branches where they are needed make
  // any difference?
  auto ac = dynamic_cast<ArithmeticCircuit *>(
      party.GetSharings().at(S_ARITH)->GetCircuitBuildRoutine());  // ARITH circuit
  auto yc = dynamic_cast<BooleanCircuit *>(
      party.GetSharings().at(S_YAO)->GetCircuitBuildRoutine());  // YAO circuit.
  assert(bc);
  assert(ac);

  share_ptr s_in_server, s_in_client;

  // share inputs in ABY
  if (context.role == SERVER) {
    s_in_server = share_ptr(bc->PutSIMDINGate(bins.size(), bins.data(), context.maxbitlen, SERVER));
    s_in_client = share_ptr(bc->PutDummySIMDINGate(bins.size(), context.maxbitlen));
  } else {
    s_in_server = share_ptr(bc->PutDummySIMDINGate(bins.size(), context.maxbitlen));
    s_in_client = share_ptr(bc->PutSIMDINGate(bins.size(), bins.data(), context.maxbitlen, CLIENT));
  }

  // compare outputs of OPPRFs for each bin in ABY (using SIMD)
  auto s_eq = share_ptr(bc->PutEQGate(s_in_server.get(), s_in_client.get()));
  // bin_result might just be for debugging. not used anywhere else right now.
  // std::vector<share_ptr> bin_results;
  // for (uint32_t i = 0; i < bins.size(); ++i) {
  //   uint32_t pos[] = {i};
  //   // subset gate to get pos({i}) of simd input at bin_results.at(i)
  //   bin_results.emplace_back(bc->PutSubsetGate(s_eq.get(), pos, 1));
  //   // output eq result share at bin_results.at(i) for both roles
  //   bin_results.at(i) = share_ptr(bc->PutOUTGate(bin_results.at(i).get(), ALL));
  // }

  share_ptr s_out;
  auto t_bitlen = static_cast<std::size_t>(std::ceil(std::log2(context.threshold)));
  // constant gate with threshold as value
  auto s_threshold = share_ptr(bc->PutCONSGate(context.threshold, t_bitlen));
  auto s_threshold_yao = share_ptr(yc->PutCONSGate(context.threshold, t_bitlen));
  std::uint64_t const_zero = 0;
  auto s_zero = share_ptr(bc->PutCONSGate(const_zero, 1));
  auto s_zero_yao = share_ptr(yc->PutCONSGate(const_zero, 1));
  std::uint64_t const_two = 2;
  auto s_two_ac = share_ptr(ac->PutCONSGate(const_two, 2));

  if (context.analytics_type == PsiAnalyticsContext::NONE) {
    // we want to only do benchmarking, so no additional operations
  } else if (context.analytics_type == PsiAnalyticsContext::THRESHOLD) {
    // split up the simd s_eq result
    auto s_eq_rotated = share_ptr(bc->PutSplitterGate(s_eq.get()));
    // hamming weight, sum of ones in the input
    s_out = share_ptr(bc->PutHammingWeightGate(s_eq_rotated.get()));
    // greater than gate (compare with threshold)
    s_out = share_ptr(bc->PutGTGate(s_out.get(), s_threshold.get()));
  } else if (context.analytics_type == PsiAnalyticsContext::SUM) {
    // same as threshold but without the GT output.

    auto s_eq_rotated = share_ptr(bc->PutSplitterGate(s_eq.get()));
    s_out = share_ptr(bc->PutHammingWeightGate(s_eq_rotated.get()));
  } else if (context.analytics_type == PsiAnalyticsContext::SUM_IF_GT_THRESHOLD) {
    auto s_eq_rotated = share_ptr(bc->PutSplitterGate(s_eq.get()));
    s_out = share_ptr(bc->PutHammingWeightGate(s_eq_rotated.get()));
    auto s_gt_t = share_ptr(bc->PutGTGate(s_out.get(), s_threshold.get()));

    // multiplexer gate for selecting zero or sum output depending on threshold
    // reached GT result.
    s_out = share_ptr(bc->PutMUXGate(s_out.get(), s_zero.get(), s_gt_t.get()));
  } else if (context.analytics_type == PsiAnalyticsContext::PAYLOAD_A_SUM ||
             context.analytics_type == PsiAnalyticsContext::PAYLOAD_A_SUM_GT) {
    share_ptr s_in_payload_a;

    // get payload shares from client
    if (context.role == SERVER) {
      s_in_payload_a = share_ptr(bc->PutDummySIMDINGate(bins.size(), context.payload_bitlen));
    } else {
      std::vector<uint64_t> payload_a(bins.size(), 0);
      for (auto i = 0ull; i < payload_a_index.size(); ++i) {
        if (payload_a_index[i] > bins.size()) {
          continue;
        }
        payload_a[i] = payload_input_a[payload_a_index[i]];
      }
      if (payload_a.size() != bins.size()) {
        std::cerr << "[Error] payload of size " << payload_a.size() << "  " << bins.size()
                  << " problem\n";
      }
      // std::cout << "payload bucket matchings" << std::endl;
      // for (auto i = 0ull; i < 100; i++) {
      //   std::cout << payload_a[i] << std::endl;
      // }
      s_in_payload_a = share_ptr(
          bc->PutSIMDINGate(payload_a.size(), payload_a.data(), context.payload_bitlen, CLIENT));
    }

    if (context.payload_bitlen == 1) {
      s_out = BuildIntersectionSumHamming(s_in_payload_a, s_eq, (BooleanCircuit *)bc);
      if (context.analytics_type == PsiAnalyticsContext::PAYLOAD_A_SUM_GT) {
        s_out = BuildGreaterThan(s_out, s_threshold, s_zero, (BooleanCircuit *)bc);
      }
    } else {
      s_out =
          BuildIntersectionSum(s_in_payload_a, s_eq, (BooleanCircuit *)bc, (ArithmeticCircuit *)ac);
      if (context.analytics_type == PsiAnalyticsContext::PAYLOAD_A_SUM_GT) {
        s_out = BuildGreaterThan(s_out, s_threshold_yao, s_zero_yao, (BooleanCircuit *)yc);
      }
    }

    // output gate
  } else {
    throw std::runtime_error("Encountered an unknown analytics type");
  }

  if (context.analytics_type == PsiAnalyticsContext::PAYLOAD_A_SUM ||
      context.analytics_type == PsiAnalyticsContext::PAYLOAD_A_SUM_GT) {
    if (context.payload_bitlen == 1) {
      s_out = share_ptr(bc->PutOUTGate(s_out.get(), ALL));
    } else {
      if (context.analytics_type == PsiAnalyticsContext::PAYLOAD_A_SUM) {
        s_out = share_ptr(ac->PutOUTGate(s_out.get(), ALL));
      } else {
        s_out = share_ptr(yc->PutOUTGate(s_out.get(), ALL));
      }
    }

  } else if (context.analytics_type != PsiAnalyticsContext::NONE) {
    s_out = share_ptr(bc->PutOUTGate(s_out.get(), ALL));
  }

  party.ExecCircuit();

  // uint64_t *output;
  // uint32_t vbitlen,vnvals;
  uint64_t output = 0;
  if (context.analytics_type != PsiAnalyticsContext::NONE) {
    output = s_out->get_clear_value<uint64_t>();
    // s_out->get_clear_value_vec(&output, &vbitlen, &vnvals);
  }

  context.timings.aby_setup = party.GetTiming(P_SETUP);
  context.timings.aby_online = party.GetTiming(P_ONLINE);
  context.timings.aby_total = context.timings.aby_setup + context.timings.aby_online;
  context.timings.base_ots_aby = party.GetTiming(P_BASE_OT);

  const auto clock_time_total_end = std::chrono::system_clock::now();
  const duration_millis clock_time_total_duration = clock_time_total_end - clock_time_total_start;
  context.timings.total = clock_time_total_duration.count();

  return output;
}

share_ptr BuildIntersectionSumHamming(share_ptr s_payload, share_ptr s_eq, BooleanCircuit *bc) {
  s_payload = share_ptr(bc->PutANDGate(s_eq.get(), s_payload.get()));
  auto s_payload_rotated = share_ptr(bc->PutSplitterGate(s_payload.get()));
  return share_ptr(bc->PutHammingWeightGate(s_payload_rotated.get()));
}

share_ptr BuildIntersectionSum(share_ptr s_payload, share_ptr s_eq, BooleanCircuit *bc,
                               ArithmeticCircuit *ac) {
  std::uint64_t const_zero = 0;

  auto s_zeros = share_ptr(bc->PutSIMDCONSGate(s_payload->get_nvals(), const_zero, 1));

  auto s_payload_mux = share_ptr(bc->PutMUXGate(s_payload.get(), s_zeros.get(), s_eq.get()));
  auto s_payload_ac = share_ptr(ac->PutB2AGate(s_payload_mux.get()));
  return BuildSum(s_payload_ac, (ArithmeticCircuit*) ac);
}

share_ptr BuildSum(share_ptr s_a, ArithmeticCircuit *ac) {
  auto nvals = s_a->get_nvals();
  s_a = share_ptr(ac->PutSplitterGate(s_a.get()));
  for (auto i = 1; i < nvals; i++) {
    s_a->set_wire_id(
        0, ac->PutADDGate(
               s_a->get_wire_id(0),
               s_a->get_wire_id(i)));  // add gates are free for arithmetic circuits
  }
  s_a->set_bitlength(1);  // we only need the result.
  return s_a;
}

share_ptr BuildGreaterThan(share_ptr s_in, share_ptr s_threshold, share_ptr s_zero,
                           BooleanCircuit *circ) {
  // GT Gate not available for Arithmetic circuit. Conversion A2B needs Yao as a
  // intermediate step. Since Yao also has GT Gate, we can do it in Yao.

  if (s_in->get_circuit_type() == C_BOOLEAN) {
    auto s_gt_t = share_ptr(circ->PutGTGate(s_in.get(), s_threshold.get()));

    // multiplexer gate for selecting zero or sum output depending on threshold
    // reached GT result.
    return share_ptr(circ->PutMUXGate(s_in.get(), s_zero.get(), s_gt_t.get()));
  } else {
    // yao circuit
    share_ptr s_in_yao = share_ptr(circ->PutA2YGate(s_in.get()));
    auto s_gt_t = share_ptr(circ->PutGTGate(s_in_yao.get(), s_threshold.get()));

    // multiplexer gate for selecting zero or sum output depending on threshold
    // reached GT result.
    return share_ptr(circ->PutMUXGate(s_in_yao.get(), s_zero.get(), s_gt_t.get()));
  }
}

// PAYLOAD_AB
uint64_t run_psi_analyticsAB(const std::vector<std::uint64_t> &inputs, PsiAnalyticsContext &context,
                             const std::vector<std::uint64_t> &payload_input_a,
                             const std::vector<std::uint64_t> &payload_input_b) {
  // establish network connection
  std::unique_ptr<CSocket> sock =
      EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));
  sock->Close();
  const auto clock_time_total_start = std::chrono::system_clock::now();

  // create hash tables from the elements
  // and create and send hints.
  std::vector<uint64_t> payload_a;
  std::vector<std::pair<uint64_t, uint64_t>> bins_2d;

  if (context.role == CLIENT) {
    std::vector<uint64_t> payload_a_index;
    bins_2d = OpprgPsiClientAB(inputs, context, payload_a_index);

    payload_a.reserve(bins_2d.size());
    for (auto &ind : payload_a_index) {
      if (ind > bins_2d.size()) {
        payload_a.push_back(0);
      } else {
        payload_a.push_back(payload_input_a[ind]);
      }
    }
  } else {
    bins_2d = OpprgPsiServerAB(inputs, context, payload_input_b);
  }

  std::vector<uint64_t> bins1;
  std::vector<uint64_t> bins2;
  bins1.reserve(bins_2d.size());
  bins2.reserve(bins_2d.size());
  for (auto i = 0ull; i < bins_2d.size(); ++i) {
    bins1.push_back(bins_2d[i].first);
    bins2.push_back(bins_2d[i].second);
  }

  // instantiate ABY
  ABYParty party(static_cast<e_role>(context.role), context.address, context.port, LT, 64,
                 context.nthreads);
  party.ConnectAndBaseOTs();
  auto bc = dynamic_cast<BooleanCircuit *>(
      party.GetSharings().at(S_BOOL)->GetCircuitBuildRoutine());  // GMW circuit
  // does moving these initiations to the if branches where they are needed make
  // any difference?
  auto ac = dynamic_cast<ArithmeticCircuit *>(
      party.GetSharings().at(S_ARITH)->GetCircuitBuildRoutine());  // ARITH circuit
  auto yc = dynamic_cast<BooleanCircuit *>(
      party.GetSharings().at(S_YAO)->GetCircuitBuildRoutine());  // YAO circuit.
  assert(bc);
  assert(ac);

  share_ptr s_in_server_1, s_in_client_1, s_in_server_2, s_in_client_2, s_in_payload_a;

  // share inputs in ABY
  if (context.role == SERVER) {
    s_in_server_1 =
        share_ptr(bc->PutSIMDINGate(bins1.size(), bins1.data(), context.maxbitlen, SERVER));
    s_in_server_2 =
        share_ptr(bc->PutSIMDINGate(bins2.size(), bins2.data(), context.maxbitlen, SERVER));
    s_in_client_1 = share_ptr(bc->PutDummySIMDINGate(bins1.size(), context.maxbitlen));
    s_in_client_2 = share_ptr(bc->PutDummySIMDINGate(bins2.size(), context.maxbitlen));
    s_in_payload_a = share_ptr(bc->PutDummySIMDINGate(bins1.size(), context.payload_bitlen));
  } else {
    s_in_server_1 = share_ptr(bc->PutDummySIMDINGate(bins1.size(), context.maxbitlen));
    s_in_server_2 = share_ptr(bc->PutDummySIMDINGate(bins2.size(), context.maxbitlen));
    s_in_client_1 =
        share_ptr(bc->PutSIMDINGate(bins1.size(), bins1.data(), context.maxbitlen, CLIENT));
    s_in_client_2 =
        share_ptr(bc->PutSIMDINGate(bins2.size(), bins2.data(), context.maxbitlen, CLIENT));
    s_in_payload_a = share_ptr(
        bc->PutSIMDINGate(payload_a.size(), payload_a.data(), context.payload_bitlen, CLIENT));
  }

  // compare outputs of OPPRFs for each bin in ABY (using SIMD)
  auto s_eq = share_ptr(bc->PutEQGate(s_in_server_1.get(), s_in_client_1.get()));

  share_ptr s_out;
  auto t_bitlen = static_cast<std::size_t>(std::ceil(std::log2(context.threshold)));
  auto s_threshold = share_ptr(bc->PutCONSGate(context.threshold, t_bitlen));
  auto s_threshold_yao = share_ptr(yc->PutCONSGate(context.threshold, t_bitlen));

  std::uint64_t const_zero = 0;
  auto s_zero = share_ptr(bc->PutCONSGate(const_zero, 1));
  auto s_zeros = share_ptr(bc->PutSIMDCONSGate(bins2.size(), const_zero, 1));
  auto s_zero_yao = share_ptr(yc->PutCONSGate(const_zero, 1));

  auto s_xor_payload_b = share_ptr(bc->PutXORGate(s_in_client_2.get(), s_in_server_2.get()));
  auto s_mux_payload_b =
      share_ptr(bc->PutMUXGate(s_xor_payload_b.get(), s_zeros.get(), s_eq.get()));
  auto s_mux_payload_a = share_ptr(bc->PutMUXGate(s_in_payload_a.get(), s_zeros.get(), s_eq.get()));

  share_ptr s_b_sum, s_a_sum, s_ab_sum, s_mul_ab;
  if (context.payload_bitlen == 1) {
    if (context.analytics_type == ENCRYPTO::PsiAnalyticsContext::PAYLOAD_AB_MUL_SUM ||
        context.analytics_type == ENCRYPTO::PsiAnalyticsContext::PAYLOAD_AB_MUL_SUM_GT) {
      s_mul_ab = share_ptr(bc->PutANDGate(s_in_payload_a.get(), s_mux_payload_b.get()));
      auto s_rotated = share_ptr(bc->PutSplitterGate(s_mul_ab.get()));
      s_ab_sum = share_ptr(bc->PutHammingWeightGate(s_rotated.get()));
    } else {
      s_a_sum = BuildIntersectionSumHamming(s_in_payload_a, s_eq, (BooleanCircuit *)bc);
      s_b_sum = BuildIntersectionSumHamming(s_mux_payload_b, s_eq, (BooleanCircuit *)bc);
      s_ab_sum = share_ptr(bc->PutADDGate(s_a_sum.get(), s_b_sum.get()));
    }
  } else {
    if (context.analytics_type == ENCRYPTO::PsiAnalyticsContext::PAYLOAD_AB_MUL_SUM ||
        context.analytics_type == ENCRYPTO::PsiAnalyticsContext::PAYLOAD_AB_MUL_SUM_GT) {
      s_mul_ab = share_ptr(bc->PutMULGate(s_mux_payload_a.get(), s_xor_payload_b.get()));
      auto s_mul_ab_ac = share_ptr(ac->PutB2AGate(s_mul_ab.get()));
      s_ab_sum = BuildSum(s_mul_ab_ac, (ArithmeticCircuit*)ac);
    } else {
      s_a_sum =
          BuildIntersectionSum(s_in_payload_a, s_eq, (BooleanCircuit *)bc, (ArithmeticCircuit *)ac);
      s_b_sum = BuildIntersectionSum(s_mux_payload_b, s_eq, (BooleanCircuit *)bc,
                                     (ArithmeticCircuit *)ac);
      s_ab_sum = share_ptr(ac->PutADDGate(s_a_sum.get(), s_b_sum.get()));
    }
    // ac->PutPrintValueGate(s_ab_sum.get(), "AB_SUM");
  }

  if (context.payload_bitlen == 1) {
    if (context.analytics_type == ENCRYPTO::PsiAnalyticsContext::PAYLOAD_AB_SUM_GT ||
        context.analytics_type == ENCRYPTO::PsiAnalyticsContext::PAYLOAD_AB_MUL_SUM_GT) {
      s_out = BuildGreaterThan(s_ab_sum, s_threshold, s_zero, (BooleanCircuit *)bc);
      s_out = share_ptr(bc->PutOUTGate(s_out.get(), ALL));
    } else {
      s_out = share_ptr(bc->PutOUTGate(s_ab_sum.get(), ALL));
    }
  } else {
    if (context.analytics_type == ENCRYPTO::PsiAnalyticsContext::PAYLOAD_AB_SUM_GT ||
        context.analytics_type == ENCRYPTO::PsiAnalyticsContext::PAYLOAD_AB_MUL_SUM_GT) {
      s_out = BuildGreaterThan(s_ab_sum, s_threshold_yao, s_zero_yao, (BooleanCircuit *)yc);
      s_out = share_ptr(yc->PutOUTGate(s_out.get(), ALL));
    } else {
      s_out = share_ptr(ac->PutOUTGate(s_ab_sum.get(), ALL));
    }
  }

  party.ExecCircuit();

  // uint64_t *output;
  // uint32_t vbitlen, vnvals;
  // s_out->get_clear_value_vec(&output, &vbitlen, &vnvals);

  uint64_t output = s_out->get_clear_value<uint64_t>();

  // if (context.analytics_type == PsiAnalyticsContext::PAYLOAD_AB_SUM) {

  // } else {
  //   throw std::runtime_error("Encountered an unknown analytics type");
  // }
  context.timings.aby_setup = party.GetTiming(P_SETUP);
  context.timings.aby_online = party.GetTiming(P_ONLINE);
  context.timings.aby_total = context.timings.aby_setup + context.timings.aby_online;
  context.timings.base_ots_aby = party.GetTiming(P_BASE_OT);

  const auto clock_time_total_end = std::chrono::system_clock::now();
  const duration_millis clock_time_total_duration = clock_time_total_end - clock_time_total_start;
  context.timings.total = clock_time_total_duration.count();

  return output;
}

std::vector<std::pair<uint64_t, uint64_t>> OpprgPsiClient(const std::vector<uint64_t> &elements,
                                                          PsiAnalyticsContext &context) {
  const auto start_time = std::chrono::system_clock::now();
  const auto hashing_start_time = std::chrono::system_clock::now();

  ENCRYPTO::CuckooTable cuckoo_table(static_cast<std::size_t>(context.nbins));
  cuckoo_table.SetNumOfHashFunctions(context.nfuns);
  cuckoo_table.Insert(elements);
  cuckoo_table.MapElements();
  // cuckoo_table.Print();

  if (cuckoo_table.GetStashSize() > 0u) {
    std::cerr << "[Error] Stash of size " << cuckoo_table.GetStashSize() << " occured\n";
  }

  auto cuckoo_table_v = cuckoo_table.AsRawVector();

  const auto hashing_end_time = std::chrono::system_clock::now();
  const duration_millis hashing_duration = hashing_end_time - hashing_start_time;
  context.timings.hashing = hashing_duration.count();
  const auto oprf_start_time = std::chrono::system_clock::now();

  // mask is the prf result for a bin
  std::vector<uint64_t> masks_with_dummies = ot_receiver(cuckoo_table_v, context);

  const auto oprf_end_time = std::chrono::system_clock::now();
  const duration_millis oprf_duration = oprf_end_time - oprf_start_time;
  context.timings.oprf = oprf_duration.count();

  std::unique_ptr<CSocket> sock =
      EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));

  const auto nbinsinmegabin = ceil_divide(context.nbins, context.nmegabins);
  std::vector<std::vector<ZpMersenneLongElement>> polynomials(context.nmegabins);
  std::vector<ZpMersenneLongElement> X(context.nbins), Y(context.nbins);
  for (auto &polynomial : polynomials) {
    polynomial.resize(context.polynomialsize);
  }

  for (auto i = 0ull; i < X.size(); ++i) {
    X.at(i).elem = masks_with_dummies.at(i);
  }

  std::vector<uint8_t> poly_rcv_buffer(context.nmegabins * context.polynomialbytelength, 0);

  const auto receiving_start_time = std::chrono::system_clock::now();

  sock->Receive(poly_rcv_buffer.data(), context.nmegabins * context.polynomialbytelength);
  sock->Close();

  const auto receiving_end_time = std::chrono::system_clock::now();
  const duration_millis sending_duration = receiving_end_time - receiving_start_time;
  context.timings.polynomials_transmission = sending_duration.count();

  const auto eval_poly_start_time = std::chrono::system_clock::now();
  for (auto poly_i = 0ull; poly_i < polynomials.size(); ++poly_i) {
    for (auto coeff_i = 0ull; coeff_i < context.polynomialsize; ++coeff_i) {
      polynomials.at(poly_i).at(coeff_i).elem = (reinterpret_cast<uint64_t *>(
          poly_rcv_buffer.data()))[poly_i * context.polynomialsize + coeff_i];
    }
  }

  for (auto i = 0ull; i < X.size(); ++i) {
    std::size_t p = i / nbinsinmegabin;
    Poly::evalMersenne(Y.at(i), polynomials.at(p), X.at(i));
  }

  const auto eval_poly_end_time = std::chrono::system_clock::now();
  const duration_millis eval_poly_duration = eval_poly_end_time - eval_poly_start_time;
  context.timings.polynomials = eval_poly_duration.count();

  std::vector<uint64_t> index_table = cuckoo_table.GetIndex();
  std::vector<std::pair<uint64_t, uint64_t>> bins_index_result;
  bins_index_result.reserve(X.size());
  for (auto i = 0ull; i < X.size(); ++i) {
    bins_index_result.push_back({X[i].elem ^ Y[i].elem, index_table[i]});
  }
  // std::cerr << "bin_index_result right after pushback" << std::endl;
  // for (auto i = 0ull; i < 10; i++) {
  //   std::cerr << bins_index_result[i].first << " " << bins_index_result[i].second << std::endl;
  // }

  const auto end_time = std::chrono::system_clock::now();
  const duration_millis total_duration = end_time - start_time;
  context.timings.total = total_duration.count();

  return bins_index_result;
}

std::vector<uint64_t> OpprgPsiServer(const std::vector<uint64_t> &elements,
                                     PsiAnalyticsContext &context) {
  const auto start_time = std::chrono::system_clock::now();

  const auto hashing_start_time = std::chrono::system_clock::now();

  // hashing server elements using simple hashing into bins.
  ENCRYPTO::SimpleTable simple_table(static_cast<std::size_t>(context.nbins));
  simple_table.SetNumOfHashFunctions(context.nfuns);
  simple_table.Insert(elements);
  simple_table.MapElements();
  // simple_table.Print();

  auto simple_table_v = simple_table.AsRaw2DVector();
  // context.simple_table = simple_table_v;

  const auto hashing_end_time = std::chrono::system_clock::now();
  const duration_millis hashing_duration = hashing_end_time - hashing_start_time;
  context.timings.hashing = hashing_duration.count();

  const auto oprf_start_time = std::chrono::system_clock::now();

  // oprf with receiver to evaluate (per bin) eachothers items. (same bin, same key)
  // masks are the oprf results of simple table elements.
  auto masks = ot_sender(simple_table_v, context);

  const auto oprf_end_time = std::chrono::system_clock::now();
  const duration_millis oprf_duration = oprf_end_time - oprf_start_time;
  context.timings.oprf = oprf_duration.count();

  const auto polynomials_start_time = std::chrono::system_clock::now();

  // creating hints of size context.polynomialsize for each megabin.
  // Hints are a polynomial interpolated on the (element, oprf-result XOR tj) pairs.
  std::vector<uint64_t> polynomials(context.nmegabins * context.polynomialsize, 0);
  std::vector<uint64_t> content_of_bins(context.nbins);

  std::random_device urandom("/dev/urandom");
  std::uniform_int_distribution<uint64_t> dist(0,
                                               (1ull << context.maxbitlen) - 1);  // [0,2^elebitlen)

  // T set.
  // generate random numbers to use for mapping the polynomial to
  std::generate(content_of_bins.begin(), content_of_bins.end(), [&]() { return dist(urandom); });
  {
    auto tmp = content_of_bins;
    std::sort(tmp.begin(), tmp.end());
    auto last = std::unique(tmp.begin(), tmp.end());
    tmp.erase(last, tmp.end());
    assert(tmp.size() == content_of_bins.size());
  }

  std::unique_ptr<CSocket> sock =
      EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));

  InterpolatePolynomials(polynomials, content_of_bins, masks, context);

  const auto polynomials_end_time = std::chrono::system_clock::now();
  const duration_millis polynomials_duration = polynomials_end_time - polynomials_start_time;
  context.timings.polynomials = polynomials_duration.count();
  const auto sending_start_time = std::chrono::system_clock::now();

  // send polynomials to the receiver
  sock->Send((uint8_t *)polynomials.data(), context.nmegabins * context.polynomialbytelength);
  sock->Close();

  const auto sending_end_time = std::chrono::system_clock::now();
  const duration_millis sending_duration = sending_end_time - sending_start_time;
  context.timings.polynomials_transmission = sending_duration.count();
  const auto end_time = std::chrono::system_clock::now();
  const duration_millis total_duration = end_time - start_time;

  return content_of_bins;
}

std::vector<std::pair<uint64_t, uint64_t>> OpprgPsiClientAB(const std::vector<uint64_t> &elements,
                                                            PsiAnalyticsContext &context,
                                                            std::vector<uint64_t> &index) {
  const auto start_time = std::chrono::system_clock::now();
  const auto hashing_start_time_1 = std::chrono::system_clock::now();

  ENCRYPTO::CuckooTable cuckoo_table(static_cast<std::size_t>(context.nbins));
  cuckoo_table.SetNumOfHashFunctions(context.nfuns);
  cuckoo_table.Insert(elements);
  cuckoo_table.MapElements();
  // cuckoo_table.Print();

  if (cuckoo_table.GetStashSize() > 0u) {
    std::cerr << "[Error] Stash of size " << cuckoo_table.GetStashSize() << " occured\n";
  }

  auto cuckoo_table_v = cuckoo_table.AsRawVector();

  const auto hashing_end_time_1 = std::chrono::system_clock::now();
  const duration_millis hashing_duration_1 = hashing_end_time_1 - hashing_start_time_1;
  context.timings.hashing = hashing_duration_1.count();
  const auto oprf_start_time_1 = std::chrono::system_clock::now();

  // mask is the prf result for a bin
  std::vector<uint64_t> masks_with_dummies = ot_receiver(cuckoo_table_v, context);

  const auto oprf_end_time_1 = std::chrono::system_clock::now();
  const duration_millis oprf_duration_1 = oprf_end_time_1 - oprf_start_time_1;
  context.timings.oprf = oprf_duration_1.count();

  std::unique_ptr<CSocket> sock =
      EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));

  const auto nbinsinmegabin = ceil_divide(context.nbins, context.nmegabins);
  std::vector<std::vector<ZpMersenneLongElement>> polynomials(context.nmegabins);
  std::vector<ZpMersenneLongElement> X(context.nbins), Y(context.nbins);
  for (auto &polynomial : polynomials) {
    polynomial.resize(context.polynomialsize);
  }

  for (auto i = 0ull; i < X.size(); ++i) {
    X.at(i).elem = masks_with_dummies.at(i);
  }

  std::vector<uint8_t> poly_rcv_buffer(context.nmegabins * context.polynomialbytelength, 0);

  const auto receiving_start_time_1 = std::chrono::system_clock::now();

  sock->Receive(poly_rcv_buffer.data(), context.nmegabins * context.polynomialbytelength);
  // sock->Close();

  const auto receiving_end_time_1 = std::chrono::system_clock::now();
  const duration_millis sending_duration_1 = receiving_end_time_1 - receiving_start_time_1;
  context.timings.polynomials_transmission = sending_duration_1.count();

  const auto eval_poly_start_time_1 = std::chrono::system_clock::now();
  for (auto poly_i = 0ull; poly_i < polynomials.size(); ++poly_i) {
    for (auto coeff_i = 0ull; coeff_i < context.polynomialsize; ++coeff_i) {
      polynomials.at(poly_i).at(coeff_i).elem = (reinterpret_cast<uint64_t *>(
          poly_rcv_buffer.data()))[poly_i * context.polynomialsize + coeff_i];
    }
  }

  for (auto i = 0ull; i < X.size(); ++i) {
    std::size_t p = i / nbinsinmegabin;
    Poly::evalMersenne(Y.at(i), polynomials.at(p), X.at(i));
  }

  const auto eval_poly_end_time_1 = std::chrono::system_clock::now();
  const duration_millis eval_poly_duration_1 = eval_poly_end_time_1 - eval_poly_start_time_1;
  context.timings.polynomials = eval_poly_duration_1.count();

  index = cuckoo_table.GetIndex();
  // std::cerr << index_table[0] << std::endl;
  // index = index_table
  // std::cerr << "bin_index_result right after pushback" << std::endl;
  // for (auto i = 0ull; i < 10; i++) {
  //   std::cerr << bins_index_result[i].first << " " << bins_index_result[i].second << std::endl;
  // }

  //////////////////////
  // OPPRF 2 for payload encryption
  // can we reuse the masks from phase 1?????/
  //////////////////////

  const auto oprf_start_time_2 = std::chrono::system_clock::now();

  // mask is the prf result for a bin
  std::vector<uint64_t> masks_with_dummies_2 = ot_receiver(cuckoo_table_v, context);

  const auto oprf_end_time_2 = std::chrono::system_clock::now();
  const duration_millis oprf_duration_2 = oprf_end_time_2 - oprf_start_time_2;
  context.timings.oprf += oprf_duration_2.count();
  // hint (polynomials) calculation
  std::vector<std::vector<ZpMersenneLongElement>> polynomials2(context.nmegabins);
  std::vector<ZpMersenneLongElement> X2(context.nbins), Y2(context.nbins);
  for (auto &polynomial : polynomials2) {
    polynomial.resize(context.polynomialsize);
  }

  for (auto i = 0ull; i < X2.size(); ++i) {
    X2.at(i).elem = masks_with_dummies_2.at(i);
  }

  std::vector<uint8_t> poly_rcv_buffer_2(context.nmegabins * context.polynomialbytelength, 0);

  const auto receiving_start_time_2 = std::chrono::system_clock::now();

  sock->Receive(poly_rcv_buffer_2.data(), context.nmegabins * context.polynomialbytelength);
  sock->Close();

  const auto receiving_end_time_2 = std::chrono::system_clock::now();
  const duration_millis sending_duration_2 = receiving_end_time_2 - receiving_start_time_2;
  context.timings.polynomials_transmission += sending_duration_2.count();

  const auto eval_poly_start_time_2 = std::chrono::system_clock::now();
  for (auto poly_i = 0ull; poly_i < polynomials2.size(); ++poly_i) {
    for (auto coeff_i = 0ull; coeff_i < context.polynomialsize; ++coeff_i) {
      polynomials2.at(poly_i).at(coeff_i).elem = (reinterpret_cast<uint64_t *>(
          poly_rcv_buffer_2.data()))[poly_i * context.polynomialsize + coeff_i];
    }
  }

  for (auto i = 0ull; i < X2.size(); ++i) {
    std::size_t p = i / nbinsinmegabin;
    Poly::evalMersenne(Y2.at(i), polynomials2.at(p), X2.at(i));
  }

  const auto eval_poly_end_time_2 = std::chrono::system_clock::now();
  const duration_millis eval_poly_duration_2 = eval_poly_end_time_2 - eval_poly_start_time_2;
  context.timings.polynomials += eval_poly_duration_2.count();

  std::vector<std::pair<uint64_t, uint64_t>> raw_bin_result;
  raw_bin_result.reserve(X.size());
  for (auto i = 0ull; i < X.size(); ++i) {
    raw_bin_result.push_back(std::make_pair(X[i].elem ^ Y[i].elem, X2[i].elem ^ Y2[i].elem));
  }

  const auto end_time = std::chrono::system_clock::now();
  const duration_millis total_duration = end_time - start_time;
  context.timings.total = total_duration.count();

  return raw_bin_result;
}

std::vector<std::pair<uint64_t, uint64_t>> OpprgPsiServerAB(
    const std::vector<uint64_t> &elements, PsiAnalyticsContext &context,
    const std::vector<std::uint64_t> &payload_input_b) {
  const auto start_time = std::chrono::system_clock::now();

  const auto hashing_start_time = std::chrono::system_clock::now();

  // hashing server elements using simple hashing into bins.
  ENCRYPTO::SimpleTable simple_table(static_cast<std::size_t>(context.nbins));
  simple_table.SetNumOfHashFunctions(context.nfuns);
  simple_table.Insert(elements);
  simple_table.MapElements();
  // simple_table.Print();

  auto simple_table_v = simple_table.AsRaw2DVector();
  std::vector<std::vector<uint64_t>> index_table = simple_table.GetIndex2D();

  // context.simple_table = simple_table_v;

  const auto hashing_end_time = std::chrono::system_clock::now();
  const duration_millis hashing_duration = hashing_end_time - hashing_start_time;
  context.timings.hashing = hashing_duration.count();

  const auto oprf_start_time_1 = std::chrono::system_clock::now();

  // oprf with receiver to evaluate (per bin) eachothers items. (same bin, same key)
  // masks are the oprf results of simple table elements.
  auto masks = ot_sender(simple_table_v, context);

  const auto oprf_end_time_1 = std::chrono::system_clock::now();
  const duration_millis oprf_duration_1 = oprf_end_time_1 - oprf_start_time_1;
  context.timings.oprf = oprf_duration_1.count();

  const auto polynomials_start_time_1 = std::chrono::system_clock::now();

  // creating hints of size context.polynomialsize for each megabin.
  // Hints are a polynomial interpolated on the (element, oprf-result XOR tj) pairs.
  std::vector<uint64_t> polynomials(context.nmegabins * context.polynomialsize, 0);
  std::vector<uint64_t> content_of_bins(context.nbins);

  std::random_device urandom("/dev/urandom");
  std::uniform_int_distribution<uint64_t> dist(0,
                                               (1ull << context.maxbitlen) - 1);  // [0,2^elebitlen)

  // T set.
  // generate random numbers to use for mapping the polynomial to
  std::generate(content_of_bins.begin(), content_of_bins.end(), [&]() { return dist(urandom); });
  {
    auto tmp = content_of_bins;
    std::sort(tmp.begin(), tmp.end());
    auto last = std::unique(tmp.begin(), tmp.end());
    tmp.erase(last, tmp.end());
    assert(tmp.size() == content_of_bins.size());
  }

  std::unique_ptr<CSocket> sock =
      EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));

  InterpolatePolynomials(polynomials, content_of_bins, masks, context);

  const auto polynomials_end_time_1 = std::chrono::system_clock::now();
  const duration_millis polynomials_duration_1 = polynomials_end_time_1 - polynomials_start_time_1;
  context.timings.polynomials = polynomials_duration_1.count();
  const auto sending_start_time_1 = std::chrono::system_clock::now();

  // send polynomials to the receiver
  sock->Send((uint8_t *)polynomials.data(), context.nmegabins * context.polynomialbytelength);
  // sock->Close();

  const auto sending_end_time_1 = std::chrono::system_clock::now();
  const duration_millis sending_duration_1 = sending_end_time_1 - sending_start_time_1;
  context.timings.polynomials_transmission = sending_duration_1.count();

  //////////////////////
  // OPPRF 2 for payload encryption
  // can we reuse the masks from phase 1?????/
  //////////////////////

  const auto oprf_start_time_2 = std::chrono::system_clock::now();

  // oprf with receiver to evaluate (per bin) eachothers items. (same bin, same key)
  // masks are the oprf results of simple table elements.
  auto masks2 = ot_sender(simple_table_v, context);

  const auto oprf_end_time_2 = std::chrono::system_clock::now();
  const duration_millis oprf_duration_2 = oprf_end_time_2 - oprf_start_time_2;
  context.timings.oprf = oprf_duration_2.count();

  const auto polynomials_start_time_2 = std::chrono::system_clock::now();

  // creating hints of size context.polynomialsize for each megabin.
  // Hints are a polynomial interpolated on the (element, oprf-result XOR tj) pairs.
  std::vector<uint64_t> polynomials2(context.nmegabins * context.polynomialsize, 0);
  std::vector<uint64_t> t_values(context.nbins);

  // std::random_device urandom("/dev/urandom");
  // std::uniform_int_distribution<uint64_t> dist(0,
  //                                              (1ull << context.maxbitlen) - 1);  //
  //                                              [0,2^elebitlen)

  // T set.
  // generate random numbers to use for mapping the polynomial to
  std::generate(t_values.begin(), t_values.end(), [&]() { return dist(urandom); });
  {
    auto tmp = t_values;
    std::sort(tmp.begin(), tmp.end());
    auto last = std::unique(tmp.begin(), tmp.end());
    tmp.erase(last, tmp.end());
    assert(tmp.size() == t_values.size());
  }

  std::vector<std::vector<uint64_t>> content_of_bins2(context.nbins);

  for (auto i = 0ull; i < context.nbins; ++i) {
    for (auto &ind : index_table[i]) {
      content_of_bins2.at(i).push_back(t_values[i] ^ payload_input_b[ind]);
    }
  }

  InterpolatePolynomials(polynomials2, content_of_bins2, masks2, context);

  const auto polynomials_end_time_2 = std::chrono::system_clock::now();
  const duration_millis polynomials_duration_2 = polynomials_end_time_2 - polynomials_start_time_2;
  context.timings.polynomials += polynomials_duration_2.count();
  const auto sending_start_time_2 = std::chrono::system_clock::now();

  // send polynomials to the receiver
  sock->Send((uint8_t *)polynomials2.data(), context.nmegabins * context.polynomialbytelength);
  sock->Close();

  const auto sending_end_time_2 = std::chrono::system_clock::now();
  const duration_millis sending_duration_2 = sending_end_time_2 - sending_start_time_2;
  context.timings.polynomials_transmission += sending_duration_2.count();

  std::vector<std::pair<uint64_t, uint64_t>> raw_bin_results;
  raw_bin_results.reserve(content_of_bins.size());
  for (auto i = 0ull; i < content_of_bins.size(); ++i) {
    raw_bin_results.push_back(std::make_pair(content_of_bins[i], t_values[i]));
  }
  const auto end_time = std::chrono::system_clock::now();
  const duration_millis total_duration = end_time - start_time;
  context.timings.total = total_duration.count();

  return raw_bin_results;
}

void InterpolatePolynomials(std::vector<uint64_t> &polynomials,
                            std::vector<uint64_t> &content_of_bins,
                            const std::vector<std::vector<uint64_t>> &masks,
                            PsiAnalyticsContext &context) {
  std::vector<std::vector<uint64_t>> contents_of_bins(content_of_bins.size());
  for (auto i = 0ull; i < contents_of_bins.size(); ++i) {
    contents_of_bins.at(i).push_back(content_of_bins[i]);
  }
  InterpolatePolynomials(polynomials, contents_of_bins, masks, context);
};

void InterpolatePolynomials(std::vector<uint64_t> &polynomials,
                            std::vector<std::vector<uint64_t>> &contents_of_bins,
                            const std::vector<std::vector<uint64_t>> &masks,
                            PsiAnalyticsContext &context) {
  std::size_t nbins = masks.size();
  std::size_t masks_offset = 0;
  std::size_t nbinsinmegabin = ceil_divide(nbins, context.nmegabins);

  for (auto mega_bin_i = 0ull; mega_bin_i < context.nmegabins; ++mega_bin_i) {
    auto polynomial = polynomials.begin() + context.polynomialsize * mega_bin_i;
    auto bin = contents_of_bins.begin() + nbinsinmegabin * mega_bin_i;
    auto masks_in_bin = masks.begin() + nbinsinmegabin * mega_bin_i;

    if ((masks_offset + nbinsinmegabin) > masks.size()) {
      auto overflow = (masks_offset + nbinsinmegabin) % masks.size();
      nbinsinmegabin -= overflow;
    }

    InterpolatePolynomialsPaddedWithDummies(polynomial, bin, masks_in_bin, nbinsinmegabin, context);
    masks_offset += nbinsinmegabin;
  }

  assert(masks_offset == masks.size());
}

void InterpolatePolynomialsPaddedWithDummies(
    std::vector<uint64_t>::iterator polynomial_offset,
    std::vector<std::vector<uint64_t>>::const_iterator random_values_in_bin,
    std::vector<std::vector<uint64_t>>::const_iterator masks_for_elems_in_bin,
    std::size_t nbins_in_megabin, PsiAnalyticsContext &context) {
  std::uniform_int_distribution<std::uint64_t> dist(0,
                                                    (1ull << context.maxbitlen) - 1);  // [0,2^61)
  std::random_device urandom("/dev/urandom");
  auto my_rand = [&urandom, &dist]() { return dist(urandom); };

  std::vector<ZpMersenneLongElement> X(context.polynomialsize), Y(context.polynomialsize),
      coeff(context.polynomialsize);

  for (auto i = 0ull, bin_counter = 0ull; i < context.polynomialsize;) {
    if (bin_counter < nbins_in_megabin) {
      if ((*masks_for_elems_in_bin).size() > 0) {
        if (context.analytics_type == PsiAnalyticsContext::PAYLOAD_AB_SUM ||
            context.analytics_type == PsiAnalyticsContext::PAYLOAD_AB_SUM_GT ||
            context.analytics_type == PsiAnalyticsContext::PAYLOAD_AB_MUL_SUM ||
            context.analytics_type == PsiAnalyticsContext::PAYLOAD_AB_MUL_SUM_GT) {
          auto &random_value = *random_values_in_bin;
          auto c = 0ull;
          for (auto &mask : *masks_for_elems_in_bin) {
            X.at(i).elem = mask & __61_bit_mask;
            Y.at(i).elem =
                X.at(i).elem ^ random_value[c];  // random_value_in_bin is t_j XOR Payload
            ++i;
            if (random_value.size() > 1) {  // only one random item per bucket (OPPRF1)
              ++c;
            }
          }
        } else {
          auto &random_value = *random_values_in_bin;
          for (auto &mask : *masks_for_elems_in_bin) {
            X.at(i).elem = mask & __61_bit_mask;
            Y.at(i).elem = X.at(i).elem ^ random_value[0];  // random_value_in_bin is t_j
            ++i;
          }
        }
      }
      ++masks_for_elems_in_bin;
      ++random_values_in_bin;  // proceed to the next bin (iterator)
      ++bin_counter;
    } else {  // generate dummy elements for polynomial interpolation
      X.at(i).elem = my_rand();
      Y.at(i).elem = my_rand();
      ++i;
    }
  }

  // interpolation
  Poly::interpolateMersenne(coeff, X, Y);

  // save polynomial in polynomial_offset var
  auto coefficient = coeff.begin();
  for (auto i = 0ull; i < coeff.size(); ++i, ++polynomial_offset, ++coefficient) {
    *polynomial_offset = (*coefficient).elem;
  }
}

std::unique_ptr<CSocket> EstablishConnection(const std::string &address, uint16_t port,
                                             e_role role) {
  std::unique_ptr<CSocket> socket;
  if (role == SERVER) {
    socket = Listen(address.c_str(), port);
  } else {
    socket = Connect(address.c_str(), port);
  }
  assert(socket);
  return socket;
}

std::size_t PlainIntersectionSize(std::vector<std::uint64_t> v1, std::vector<std::uint64_t> v2) {
  std::vector<std::uint64_t> intersection_v;

  std::sort(v1.begin(), v1.end());
  std::sort(v2.begin(), v2.end());

  std::set_intersection(v1.begin(), v1.end(), v2.begin(), v2.end(), back_inserter(intersection_v));
  return intersection_v.size();
}

void PrintTimings(const PsiAnalyticsContext &context) {
  std::cout << "Time for hashing " << context.timings.hashing << " ms\n";
  std::cout << "Time for OPRF " << context.timings.oprf << " ms\n";
  std::cout << "Time for polynomials " << context.timings.polynomials << " ms\n";
  std::cout << "Time for transmission of the polynomials "
            << context.timings.polynomials_transmission << " ms\n";
  //  std::cout << "Time for OPPRF " << context.timings.opprf << " ms\n";

  std::cout << "ABY timings: online time " << context.timings.aby_online << " ms, setup time "
            << context.timings.aby_setup << " ms, total time " << context.timings.aby_total
            << " ms\n";

  std::cout << "Total runtime: " << context.timings.total << "ms\n";
  std::cout << "Total runtime w/o base OTs: "
            << context.timings.total - context.timings.base_ots_aby -
                   context.timings.base_ots_libote
            << "ms\n";
}

}  // namespace ENCRYPTO
