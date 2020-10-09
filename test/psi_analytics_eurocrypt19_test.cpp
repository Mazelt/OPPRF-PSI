//
// \file psi_analytics_eurocrypt19_test.cpp
// \author Oleksandr Tkachenko
// \email tkachenko@encrypto.cs.tu-darmstadt.de
// \organization Cryptography and Privacy Engineering Group (ENCRYPTO)
// \TU Darmstadt, Computer Science department
//
// \copyright The MIT License. Copyright Oleksandr Tkachenko

#include <thread>

#include "gtest/gtest.h"

#include "common/psi_analytics.h"
#include "common/psi_analytics_context.h"

#include "HashingTables/cuckoo_hashing/cuckoo_hashing.h"
#include "HashingTables/simple_hashing/simple_hashing.h"

constexpr std::size_t ITERATIONS = 1;

constexpr std::size_t NELES_2_12 = 1ull << 12, NELES_2_16 = 1ull << 16, NELES_2_20 = 1ull << 20;
constexpr std::size_t POLYNOMIALSIZE_2_12 = 975, POLYNOMIALSIZE_2_16 = 1021,
                      POLYNOMIALSIZE_2_20 = 1024;
constexpr std::size_t NMEGABINS_2_12 = 16, NMEGABINS_2_16 = 248, NMEGABINS_2_20 = 4002;

auto CreateContext(e_role role, uint64_t neles, uint64_t polynomialsize, uint64_t nmegabins) {
  return ENCRYPTO::PsiAnalyticsContext{7777,  // port
                                       role,
                                       61,  // bitlength
                                       neles,
                                       static_cast<uint64_t>(neles * 1.27f),
                                       0,  // # other party's elements, i.e., =neles
                                       1,  // # threads
                                       3,  // # hash functions
                                       1,  // threshold
                                       polynomialsize,
                                       polynomialsize * sizeof(uint64_t),
                                       nmegabins,
                                       1.27f,  // epsilon
                                       "127.0.0.1",
                                       0,  // payload_a_bitlen
                                       ENCRYPTO::PsiAnalyticsContext::SUM};
}

bool comp(const std::pair<uint64_t, uint64_t> &a, const std::pair<uint64_t, uint64_t> &b) {
  return a.first < b.first;
}

auto PlaintextPayloadSum(std::vector<uint64_t> v1, std::vector<uint64_t> v2,
                         std::vector<uint64_t> p_1) {
  // ATTENTION: payload is sorted after the v1 vector's order.!!!!!
  std::vector<std::pair<uint64_t, uint64_t>> v1_p;
  std::vector<std::pair<uint64_t, uint64_t>> v2_p;  // dummy
  std::vector<std::pair<uint64_t, uint64_t>> intersection_p;

  for (auto i = 0; i < v1.size(); ++i) {
    v1_p.push_back(std::make_pair(v1[i], p_1[i]));
  }

  for (auto i = 0; i < v2.size(); ++i) {
    v2_p.push_back(std::make_pair(v2[i], 0));
  }
  std::sort(v1_p.begin(), v1_p.end());
  std::sort(v2_p.begin(), v2_p.end());

  std::set_intersection(v1_p.begin(), v1_p.end(), v2_p.begin(), v2_p.end(),
                        back_inserter(intersection_p), comp);

  uint64_t sum = 0;
  for (auto i = 0; i < intersection_p.size(); ++i) {
    sum += intersection_p[i].second;
  }
  // std::cout << "SUM" << sum << std::endl;
  return sum;
}

auto PlaintextPayloadSum(std::vector<uint64_t> v1, std::vector<uint64_t> v2,
                         std::vector<uint64_t> p_1, std::vector<uint64_t> p_2) {
  std::vector<std::pair<uint64_t, uint64_t>> v1_p;
  std::vector<std::pair<uint64_t, uint64_t>> v2_p;  // dummy
  std::vector<std::pair<uint64_t, uint64_t>> intersection_p_1;
  std::vector<std::pair<uint64_t, uint64_t>> intersection_p_2;

  for (auto i = 0; i < v1.size(); ++i) {
    v1_p.push_back(std::make_pair(v1[i], p_1[i]));
  }

  for (auto i = 0; i < v2.size(); ++i) {
    v2_p.push_back(std::make_pair(v2[i], p_2[i]));
  }
  std::sort(v1_p.begin(), v1_p.end());
  std::sort(v2_p.begin(), v2_p.end());

  std::set_intersection(v1_p.begin(), v1_p.end(), v2_p.begin(), v2_p.end(),
                        back_inserter(intersection_p_1), comp);
  std::set_intersection(v2_p.begin(), v2_p.end(), v1_p.begin(), v1_p.end(),
                        back_inserter(intersection_p_2), comp);
  uint64_t sum = 0;
  for (auto i = 0; i < intersection_p_1.size(); ++i) {
    sum += intersection_p_1[i].second + intersection_p_2[i].second;
  }
  // std::cout << "SUM" << sum << std::endl;
  return sum;
}

auto PlaintextPayloadMulSum(std::vector<uint64_t> v1, std::vector<uint64_t> v2,
                            std::vector<uint64_t> p_1, std::vector<uint64_t> p_2) {

  std::vector<std::pair<uint64_t, uint64_t>> v1_p;
  std::vector<std::pair<uint64_t, uint64_t>> v2_p;  // dummy
  std::vector<std::pair<uint64_t, uint64_t>> intersection_p_1;
  std::vector<std::pair<uint64_t, uint64_t>> intersection_p_2;

  for (auto i = 0; i < v1.size(); ++i) {
    v1_p.push_back(std::make_pair(v1[i], p_1[i]));
  }

  for (auto i = 0; i < v2.size(); ++i) {
    v2_p.push_back(std::make_pair(v2[i], p_2[i]));
  }
  std::sort(v1_p.begin(), v1_p.end());
  std::sort(v2_p.begin(), v2_p.end());

  std::set_intersection(v1_p.begin(), v1_p.end(), v2_p.begin(), v2_p.end(),
                        back_inserter(intersection_p_1), comp);
  std::set_intersection(v2_p.begin(), v2_p.end(), v1_p.begin(), v1_p.end(),
                        back_inserter(intersection_p_2), comp);
  uint64_t sum = 0;
  for (auto i = 0; i < intersection_p_1.size(); ++i) {
    sum += intersection_p_1[i].second * intersection_p_2[i].second;
  }
  // std::cout << "SUM" << sum << std::endl;
  return sum;
}

void PsiAnalyticsThresholdTest(ENCRYPTO::PsiAnalyticsContext client_context,
                               ENCRYPTO::PsiAnalyticsContext server_context) {
  auto client_inputs = ENCRYPTO::GeneratePseudoRandomElements(client_context.neles, 15);
  auto server_inputs = ENCRYPTO::GeneratePseudoRandomElements(server_context.neles, 15);

  auto plain_intersection_size = ENCRYPTO::PlainIntersectionSize(client_inputs, server_inputs);
  assert(plain_intersection_size != 0);
  server_context.threshold = client_context.threshold = plain_intersection_size - 1;

  std::uint64_t psi_client, psi_server;

  // threshold < intersection, should yield 1
  {
    std::thread client_thread(
        [&]() { psi_client = run_psi_analytics(client_inputs, client_context); });
    std::thread server_thread(
        [&]() { psi_server = run_psi_analytics(server_inputs, server_context); });

    client_thread.join();
    server_thread.join();

    ASSERT_EQ(psi_client, 1u);
    ASSERT_EQ(psi_server, 1u);
  }

  server_context.threshold = client_context.threshold = plain_intersection_size + 1;

  // threshold > intersection, should yield 0
  {
    std::thread client_thread(
        [&]() { psi_client = run_psi_analytics(client_inputs, client_context); });
    std::thread server_thread(
        [&]() { psi_server = run_psi_analytics(server_inputs, server_context); });

    client_thread.join();
    server_thread.join();

    ASSERT_EQ(psi_client, 0u);
    ASSERT_EQ(psi_server, 0u);
  }
}

void PsiAnalyticsSumIfGtThresholdTest(ENCRYPTO::PsiAnalyticsContext client_context,
                                      ENCRYPTO::PsiAnalyticsContext server_context) {
  auto client_inputs = ENCRYPTO::GeneratePseudoRandomElements(client_context.neles, 15, 0);
  auto server_inputs = ENCRYPTO::GeneratePseudoRandomElements(client_context.neles, 15, 1);

  auto plain_intersection_size = ENCRYPTO::PlainIntersectionSize(client_inputs, server_inputs);
  assert(plain_intersection_size != 0);
  client_context.threshold = plain_intersection_size - 1;
  server_context.threshold = client_context.threshold;

  std::uint64_t psi_client, psi_server;

  // threshold < intersection, should yield the intersection size
  {
    std::thread client_thread(
        [&]() { psi_client = run_psi_analytics(client_inputs, client_context); });
    std::thread server_thread(
        [&]() { psi_server = run_psi_analytics(server_inputs, server_context); });

    client_thread.join();
    server_thread.join();

    ASSERT_EQ(psi_client, plain_intersection_size);
    ASSERT_EQ(psi_server, plain_intersection_size);
  }

  server_context.threshold = client_context.threshold = plain_intersection_size + 1;

  // threshold > intersection, should yield 0
  {
    std::thread client_thread(
        [&]() { psi_client = run_psi_analytics(client_inputs, client_context); });
    std::thread server_thread(
        [&]() { psi_server = run_psi_analytics(server_inputs, server_context); });

    client_thread.join();
    server_thread.join();

    ASSERT_EQ(psi_client, 0u);
    ASSERT_EQ(psi_server, 0u);
  }
}

void PsiAnalyticsSumTest(ENCRYPTO::PsiAnalyticsContext client_context,
                         ENCRYPTO::PsiAnalyticsContext server_context) {
  auto client_inputs = ENCRYPTO::GeneratePseudoRandomElements(client_context.neles, 15, 0);
  auto server_inputs = ENCRYPTO::GeneratePseudoRandomElements(client_context.neles, 15, 1);

  auto plain_intersection_size = ENCRYPTO::PlainIntersectionSize(client_inputs, server_inputs);
  assert(plain_intersection_size != 0);
  client_context.threshold = plain_intersection_size - 1;
  server_context.threshold = client_context.threshold;

  std::uint64_t psi_client, psi_server;

  {
    std::thread client_thread(
        [&]() { psi_client = run_psi_analytics(client_inputs, client_context); });
    std::thread server_thread(
        [&]() { psi_server = run_psi_analytics(server_inputs, server_context); });

    client_thread.join();
    server_thread.join();

    ASSERT_EQ(psi_client, plain_intersection_size);
    ASSERT_EQ(psi_server, plain_intersection_size);
  }

  server_context.threshold = client_context.threshold = plain_intersection_size + 1;

  {
    std::thread client_thread(
        [&]() { psi_client = run_psi_analytics(client_inputs, client_context); });
    std::thread server_thread(
        [&]() { psi_server = run_psi_analytics(server_inputs, server_context); });

    client_thread.join();
    server_thread.join();

    ASSERT_EQ(psi_client, plain_intersection_size);
    ASSERT_EQ(psi_server, plain_intersection_size);
  }
}

void PsiAnalyticsPayloadASumTest(ENCRYPTO::PsiAnalyticsContext client_context,
                                 ENCRYPTO::PsiAnalyticsContext server_context) {
  auto client_inputs = ENCRYPTO::GeneratePseudoRandomElements(client_context.neles, 15, 0);
  auto server_inputs = ENCRYPTO::GeneratePseudoRandomElements(server_context.neles, 15, 0);

  auto plain_intersection_size = ENCRYPTO::PlainIntersectionSize(client_inputs, server_inputs);
  assert(plain_intersection_size != 0);

  std::vector<uint64_t> payload_a =
      ENCRYPTO::GenerateRandomPayload(client_context.neles, client_context.payload_bitlen, 2);

  auto plain_intersection_payload_sum =
      PlaintextPayloadSum(client_inputs, server_inputs, payload_a);

  std::uint64_t psi_client, psi_server;

  {
    std::thread client_thread(
        [&]() { psi_client = run_psi_analytics(client_inputs, client_context, payload_a); });
    std::thread server_thread(
        [&]() { psi_server = run_psi_analytics(server_inputs, server_context); });

    client_thread.join();
    server_thread.join();

    ASSERT_EQ(psi_client, plain_intersection_payload_sum);
    ASSERT_EQ(psi_server, plain_intersection_payload_sum);
  }
}

void PsiAnalyticsPayloadASumGTTest(ENCRYPTO::PsiAnalyticsContext client_context,
                                   ENCRYPTO::PsiAnalyticsContext server_context) {
  auto client_inputs = ENCRYPTO::GeneratePseudoRandomElements(client_context.neles, 15, 0);
  auto server_inputs = ENCRYPTO::GeneratePseudoRandomElements(server_context.neles, 15, 1);

  auto plain_intersection_size = ENCRYPTO::PlainIntersectionSize(client_inputs, server_inputs);
  assert(plain_intersection_size != 0);

  std::vector<uint64_t> payload_a =
      ENCRYPTO::GenerateRandomPayload(client_context.neles, client_context.payload_bitlen, 2);

  auto plain_intersection_payload_sum =
      PlaintextPayloadSum(client_inputs, server_inputs, payload_a);
  assert(plain_intersection_payload_sum != 0);

  client_context.threshold = plain_intersection_payload_sum - 1;
  server_context.threshold = client_context.threshold;

  std::uint64_t psi_client, psi_server;

  {
    std::thread client_thread(
        [&]() { psi_client = run_psi_analytics(client_inputs, client_context, payload_a); });
    std::thread server_thread(
        [&]() { psi_server = run_psi_analytics(server_inputs, server_context); });

    client_thread.join();
    server_thread.join();

    ASSERT_EQ(psi_client, plain_intersection_payload_sum);
    ASSERT_EQ(psi_server, plain_intersection_payload_sum);
  }

  server_context.threshold = client_context.threshold = plain_intersection_payload_sum + 1;

  // should return 0 as payload intersection sum is < threshold
  {
    std::thread client_thread(
        [&]() { psi_client = run_psi_analytics(client_inputs, client_context, payload_a); });
    std::thread server_thread(
        [&]() { psi_server = run_psi_analytics(server_inputs, server_context); });

    client_thread.join();
    server_thread.join();

    ASSERT_EQ(psi_client, 0u);
    ASSERT_EQ(psi_server, 0u);
  }
}

void PsiAnalyticsPayloadABSumTest(ENCRYPTO::PsiAnalyticsContext client_context,
                                  ENCRYPTO::PsiAnalyticsContext server_context) {
  auto client_inputs = ENCRYPTO::GeneratePseudoRandomElements(client_context.neles, 15, 0);
  auto server_inputs = ENCRYPTO::GeneratePseudoRandomElements(server_context.neles, 15, 1);
  auto plain_intersection_size = ENCRYPTO::PlainIntersectionSize(client_inputs, server_inputs);
  assert(plain_intersection_size != 0);

  std::vector<uint64_t> payload_a =
      ENCRYPTO::GenerateRandomPayload(client_context.neles, client_context.payload_bitlen, 2);
  std::vector<uint64_t> payload_b =
      ENCRYPTO::GenerateRandomPayload(server_context.neles, client_context.payload_bitlen, 3);
  auto plain_intersection_payload_ab_sum =
      PlaintextPayloadSum(client_inputs, server_inputs, payload_a, payload_b);

  std::vector<uint64_t> dummy_payload;

  std::uint64_t psi_client, psi_server;

  {
    std::thread client_thread([&]() {
      psi_client = run_psi_analyticsAB(client_inputs, client_context, payload_a, dummy_payload);
    });
    std::thread server_thread([&]() {
      psi_server = run_psi_analyticsAB(server_inputs, server_context, dummy_payload, payload_b);
    });

    client_thread.join();
    server_thread.join();

    ASSERT_EQ(psi_client, plain_intersection_payload_ab_sum);
    ASSERT_EQ(psi_server, plain_intersection_payload_ab_sum);
  }
}

void PsiAnalyticsPayloadABSumGTTest(ENCRYPTO::PsiAnalyticsContext client_context,
                                    ENCRYPTO::PsiAnalyticsContext server_context) {
  auto client_inputs = ENCRYPTO::GeneratePseudoRandomElements(client_context.neles, 15, 0);
  auto server_inputs = ENCRYPTO::GeneratePseudoRandomElements(server_context.neles, 15, 1);
  auto plain_intersection_size = ENCRYPTO::PlainIntersectionSize(client_inputs, server_inputs);
  assert(plain_intersection_size != 0);
  std::vector<uint64_t> payload_a =
      ENCRYPTO::GenerateRandomPayload(client_context.neles, client_context.payload_bitlen, 2);
  std::vector<uint64_t> payload_b =
      ENCRYPTO::GenerateRandomPayload(server_context.neles, client_context.payload_bitlen, 3);
  auto plain_intersection_payload_ab_sum =
      PlaintextPayloadSum(client_inputs, server_inputs, payload_a, payload_b);
  // std::cout << "plain inter ab sum " << plain_intersection_payload_ab_sum;
  client_context.threshold = plain_intersection_payload_ab_sum - 1;
  server_context.threshold = client_context.threshold;
  std::vector<uint64_t> dummy_payload;

  std::uint64_t psi_client, psi_server;

  {
    std::thread client_thread([&]() {
      psi_client = run_psi_analyticsAB(client_inputs, client_context, payload_a, dummy_payload);
    });
    std::thread server_thread([&]() {
      psi_server = run_psi_analyticsAB(server_inputs, server_context, dummy_payload, payload_b);
    });

    client_thread.join();
    server_thread.join();

    ASSERT_EQ(psi_client, plain_intersection_payload_ab_sum);
    ASSERT_EQ(psi_server, plain_intersection_payload_ab_sum);
  }

  server_context.threshold = client_context.threshold = plain_intersection_payload_ab_sum + 1;

  // should return 0 as payload intersection sum is < threshold
  {
    std::thread client_thread([&]() {
      psi_client = run_psi_analyticsAB(client_inputs, client_context, payload_a, dummy_payload);
    });
    std::thread server_thread([&]() {
      psi_server = run_psi_analyticsAB(server_inputs, server_context, dummy_payload, payload_b);
    });

    client_thread.join();
    server_thread.join();

    ASSERT_EQ(psi_client, 0u);
    ASSERT_EQ(psi_server, 0u);
  }
}

void PsiAnalyticsPayloadABMulSumTest(ENCRYPTO::PsiAnalyticsContext client_context,
                                     ENCRYPTO::PsiAnalyticsContext server_context) {
  auto client_inputs = ENCRYPTO::GeneratePseudoRandomElements(client_context.neles, 15, 0);
  auto server_inputs = ENCRYPTO::GeneratePseudoRandomElements(server_context.neles, 15, 1);
  auto plain_intersection_size = ENCRYPTO::PlainIntersectionSize(client_inputs, server_inputs);
  assert(plain_intersection_size != 0);

  std::vector<uint64_t> payload_a =
      ENCRYPTO::GenerateRandomPayload(client_context.neles, client_context.payload_bitlen, 2);
  std::vector<uint64_t> payload_b =
      ENCRYPTO::GenerateRandomPayload(server_context.neles, client_context.payload_bitlen, 3);

  auto plain_intersection_payload_ab_mul_sum = PlaintextPayloadMulSum(client_inputs, server_inputs, payload_a, payload_b);
  
  // std::cout << "plain inter ab sum " << plain_intersection_payload_ab_sum;

  std::vector<uint64_t> dummy_payload;

  std::uint64_t psi_client, psi_server;

  {
    std::thread client_thread([&]() {
      psi_client = run_psi_analyticsAB(client_inputs, client_context, payload_a, dummy_payload);
    });
    std::thread server_thread([&]() {
      psi_server = run_psi_analyticsAB(server_inputs, server_context, dummy_payload, payload_b);
    });

    client_thread.join();
    server_thread.join();

    ASSERT_EQ(psi_client, plain_intersection_payload_ab_mul_sum);
    ASSERT_EQ(psi_server, plain_intersection_payload_ab_mul_sum);
  }
}

void PsiAnalyticsPayloadABMulSumGTTest(ENCRYPTO::PsiAnalyticsContext client_context,
                                       ENCRYPTO::PsiAnalyticsContext server_context) {
  auto client_inputs = ENCRYPTO::GeneratePseudoRandomElements(client_context.neles, 15, 0);
  auto server_inputs = ENCRYPTO::GeneratePseudoRandomElements(server_context.neles, 15, 1);
  auto plain_intersection_size = ENCRYPTO::PlainIntersectionSize(client_inputs, server_inputs);
  assert(plain_intersection_size != 0);

  std::vector<uint64_t> payload_a =
      ENCRYPTO::GenerateRandomPayload(client_context.neles, client_context.payload_bitlen, 2);
  std::vector<uint64_t> payload_b =
      ENCRYPTO::GenerateRandomPayload(server_context.neles, client_context.payload_bitlen, 3);

  auto plain_intersection_payload_ab_mul_sum =
      PlaintextPayloadMulSum(client_inputs, server_inputs, payload_a, payload_b);

  // std::cout << "plain inter ab sum " << plain_intersection_payload_ab_sum;
  client_context.threshold = plain_intersection_payload_ab_mul_sum - 1;
  server_context.threshold = client_context.threshold;
  std::vector<uint64_t> dummy_payload;

  std::uint64_t psi_client, psi_server;

  {
    std::thread client_thread([&]() {
      psi_client = run_psi_analyticsAB(client_inputs, client_context, payload_a, dummy_payload);
    });
    std::thread server_thread([&]() {
      psi_server = run_psi_analyticsAB(server_inputs, server_context, dummy_payload, payload_b);
    });

    client_thread.join();
    server_thread.join();

    ASSERT_EQ(psi_client, plain_intersection_payload_ab_mul_sum);
    ASSERT_EQ(psi_server, plain_intersection_payload_ab_mul_sum);
  }

  server_context.threshold = client_context.threshold = plain_intersection_payload_ab_mul_sum + 1;

  // should return 0 as payload intersection sum is < threshold
  {
    std::thread client_thread([&]() {
      psi_client = run_psi_analyticsAB(client_inputs, client_context, payload_a, dummy_payload);
    });
    std::thread server_thread([&]() {
      psi_server = run_psi_analyticsAB(server_inputs, server_context, dummy_payload, payload_b);
    });

    client_thread.join();
    server_thread.join();

    ASSERT_EQ(psi_client, 0u);
    ASSERT_EQ(psi_server, 0u);
  }
}

void PsiAnalyticsTest(std::size_t elem_bitlen, bool random, uint64_t neles, uint64_t polynomialsize,
                      uint64_t nmegabins) {
  auto client_context = CreateContext(CLIENT, neles, polynomialsize, nmegabins);
  auto server_context = CreateContext(SERVER, neles, polynomialsize, nmegabins);

  auto client_inputs =
      random ? ENCRYPTO::GeneratePseudoRandomElements(client_context.neles, elem_bitlen, 0)
             : ENCRYPTO::GenerateSequentialElements(client_context.neles);
  auto server_inputs =
      random ? ENCRYPTO::GeneratePseudoRandomElements(client_context.neles, elem_bitlen, 1)
             : ENCRYPTO::GenerateSequentialElements(client_context.neles);

  std::uint64_t psi_client, psi_server;

  std::thread client_thread(
      [&]() { psi_client = run_psi_analytics(client_inputs, client_context); });
  std::thread server_thread(
      [&]() { psi_server = run_psi_analytics(server_inputs, server_context); });

  client_thread.join();
  server_thread.join();

  auto plain_intersection_size = ENCRYPTO::PlainIntersectionSize(client_inputs, server_inputs);

  ASSERT_EQ(psi_client, plain_intersection_size);
  ASSERT_EQ(psi_server, plain_intersection_size);
}

TEST(PSI_ANALYTICS, pow_2_12_payABMulGT) {
  for (auto i = 0ull; i < ITERATIONS; ++i) {
    // client's context
    ENCRYPTO::PsiAnalyticsContext cc{7777,  // port
                                     CLIENT,
                                     61,  // bitlength
                                     NELES_2_12,
                                     static_cast<uint64_t>(NELES_2_12 * 1.27f),
                                     0,  // # other party's elements
                                     1,  // # threads
                                     3,  // # hash functions
                                     1,  // threshold
                                     POLYNOMIALSIZE_2_12,
                                     POLYNOMIALSIZE_2_12 * sizeof(uint64_t),
                                     NMEGABINS_2_12,
                                     1.27f,  // epsilon
                                     "127.0.0.1",
                                     2,  // payload_a_bitlen
                                     ENCRYPTO::PsiAnalyticsContext::PAYLOAD_AB_MUL_SUM_GT};

    // server's context
    ENCRYPTO::PsiAnalyticsContext sc{7777,  // port
                                     SERVER,
                                     61,  // bitlength
                                     NELES_2_12,
                                     static_cast<uint64_t>(NELES_2_12 * 1.27f),
                                     0,  // # other party's elements
                                     1,  // # threads
                                     3,  // # hash functions
                                     1,  // threshold
                                     POLYNOMIALSIZE_2_12,
                                     POLYNOMIALSIZE_2_12 * sizeof(uint64_t),
                                     NMEGABINS_2_12,
                                     1.27f,  // epsilon
                                     "127.0.0.1",
                                     2,  // payload_a_bitlen
                                     ENCRYPTO::PsiAnalyticsContext::PAYLOAD_AB_MUL_SUM_GT};
    PsiAnalyticsPayloadABMulSumGTTest(cc, sc);
  }
}

TEST(PSI_ANALYTICS, pow_2_12_payABMul) {
  for (auto i = 0ull; i < ITERATIONS; ++i) {
    // client's context
    ENCRYPTO::PsiAnalyticsContext cc{7777,  // port
                                     CLIENT,
                                     61,  // bitlength
                                     NELES_2_12,
                                     static_cast<uint64_t>(NELES_2_12 * 1.27f),
                                     0,  // # other party's elements
                                     1,  // # threads
                                     3,  // # hash functions
                                     1,  // threshold
                                     POLYNOMIALSIZE_2_12,
                                     POLYNOMIALSIZE_2_12 * sizeof(uint64_t),
                                     NMEGABINS_2_12,
                                     1.27f,  // epsilon
                                     "127.0.0.1",
                                     2,  // payload_a_bitlen
                                     ENCRYPTO::PsiAnalyticsContext::PAYLOAD_AB_MUL_SUM};

    // server's context
    ENCRYPTO::PsiAnalyticsContext sc{7777,  // port
                                     SERVER,
                                     61,  // bitlength
                                     NELES_2_12,
                                     static_cast<uint64_t>(NELES_2_12 * 1.27f),
                                     0,  // # other party's elements
                                     1,  // # threads
                                     3,  // # hash functions
                                     1,  // threshold
                                     POLYNOMIALSIZE_2_12,
                                     POLYNOMIALSIZE_2_12 * sizeof(uint64_t),
                                     NMEGABINS_2_12,
                                     1.27f,  // epsilon
                                     "127.0.0.1",
                                     2,  // payload_a_bitlen
                                     ENCRYPTO::PsiAnalyticsContext::PAYLOAD_AB_MUL_SUM};
    PsiAnalyticsPayloadABMulSumTest(cc, sc);
  }
}


TEST(PSI_ANALYTICS, helper_function_test){
  std::vector<uint64_t> elements_a = {1,2,3,4,5,6,7,8};
  std::vector<uint64_t> elements_b = {4,5,6,7,8,9,10,11};
  std::vector<uint64_t> payload_a =  {1,2,3,4,5,6,7,8};
  std::vector<uint64_t> payload_b =  {11,12,13,14,15,16,17,18};

  auto plaintextIntesectionSize = ENCRYPTO::PlainIntersectionSize(elements_a, elements_b);
  ASSERT_EQ(plaintextIntesectionSize, 5);
  auto plaintextIntersectionASum = PlaintextPayloadSum(elements_a, elements_b, payload_a);
  ASSERT_EQ(plaintextIntersectionASum, 4+5+6+7+8);
  auto plaintextIntersectionBSum = PlaintextPayloadSum(elements_b, elements_a, payload_b);
  ASSERT_EQ(plaintextIntersectionBSum, 11+12+13+14+15);
  auto plaintextIntersectionABSum = PlaintextPayloadSum(elements_a, elements_b, payload_a, payload_b);
  ASSERT_EQ(plaintextIntersectionABSum, plaintextIntersectionASum + plaintextIntersectionBSum);
  auto plaintextIntersectionABMulSum = PlaintextPayloadMulSum(elements_a, elements_b, payload_a, payload_b);
  ASSERT_EQ(plaintextIntersectionABMulSum, 4*11+5*12+6*13+7*14+8*15);
}

TEST(PSI_ANALYTICS, pow_2_12_payABGT) {
  for (auto i = 0ull; i < ITERATIONS; ++i) {
    // client's context
    ENCRYPTO::PsiAnalyticsContext cc{7777,  // port
                                     CLIENT,
                                     61,  // bitlength
                                     NELES_2_12,
                                     static_cast<uint64_t>(NELES_2_12 * 1.27f),
                                     0,  // # other party's elements
                                     1,  // # threads
                                     3,  // # hash functions
                                     1,  // threshold
                                     POLYNOMIALSIZE_2_12,
                                     POLYNOMIALSIZE_2_12 * sizeof(uint64_t),
                                     NMEGABINS_2_12,
                                     1.27f,  // epsilon
                                     "127.0.0.1",
                                     2,  // payload_a_bitlen
                                     ENCRYPTO::PsiAnalyticsContext::PAYLOAD_AB_SUM_GT};

    // server's context
    ENCRYPTO::PsiAnalyticsContext sc{7777,  // port
                                     SERVER,
                                     61,  // bitlength
                                     NELES_2_12,
                                     static_cast<uint64_t>(NELES_2_12 * 1.27f),
                                     0,  // # other party's elements
                                     1,  // # threads
                                     3,  // # hash functions
                                     1,  // threshold
                                     POLYNOMIALSIZE_2_12,
                                     POLYNOMIALSIZE_2_12 * sizeof(uint64_t),
                                     NMEGABINS_2_12,
                                     1.27f,  // epsilon
                                     "127.0.0.1",
                                     2,  // payload_a_bitlen
                                     ENCRYPTO::PsiAnalyticsContext::PAYLOAD_AB_SUM_GT};
    PsiAnalyticsPayloadABSumGTTest(cc, sc);
  }
}

TEST(PSI_ANALYTICS, pow_2_12_payAB) {
  for (auto i = 0ull; i < ITERATIONS; ++i) {
    // client's context
    ENCRYPTO::PsiAnalyticsContext cc{7777,  // port
                                     CLIENT,
                                     61,  // bitlength
                                     NELES_2_12,
                                     static_cast<uint64_t>(NELES_2_12 * 1.27f),
                                     0,  // # other party's elements
                                     1,  // # threads
                                     3,  // # hash functions
                                     1,  // threshold
                                     POLYNOMIALSIZE_2_12,
                                     POLYNOMIALSIZE_2_12 * sizeof(uint64_t),
                                     NMEGABINS_2_12,
                                     1.27f,  // epsilon
                                     "127.0.0.1",
                                     2,  // payload_a_bitlen
                                     ENCRYPTO::PsiAnalyticsContext::PAYLOAD_AB_SUM};

    // server's context
    ENCRYPTO::PsiAnalyticsContext sc{7777,  // port
                                     SERVER,
                                     61,  // bitlength
                                     NELES_2_12,
                                     static_cast<uint64_t>(NELES_2_12 * 1.27f),
                                     0,  // # other party's elements
                                     1,  // # threads
                                     3,  // # hash functions
                                     1,  // threshold
                                     POLYNOMIALSIZE_2_12,
                                     POLYNOMIALSIZE_2_12 * sizeof(uint64_t),
                                     NMEGABINS_2_12,
                                     1.27f,  // epsilon
                                     "127.0.0.1",
                                     2,  // payload_a_bitlen
                                     ENCRYPTO::PsiAnalyticsContext::PAYLOAD_AB_SUM};
    PsiAnalyticsPayloadABSumTest(cc, sc);
  }
}

TEST(PSI_ANALYTICS, pow_2_12_payAGT) {
  for (auto i = 0ull; i < ITERATIONS; ++i) {
    // client's context
    ENCRYPTO::PsiAnalyticsContext cc{7777,  // port
                                     CLIENT,
                                     61,  // bitlength
                                     NELES_2_12,
                                     static_cast<uint64_t>(NELES_2_12 * 1.27f),
                                     0,  // # other party's elements
                                     1,  // # threads
                                     3,  // # hash functions
                                     1,  // threshold
                                     POLYNOMIALSIZE_2_12,
                                     POLYNOMIALSIZE_2_12 * sizeof(uint64_t),
                                     NMEGABINS_2_12,
                                     1.27f,  // epsilon
                                     "127.0.0.1",
                                     2,  // payload_a_bitlen
                                     ENCRYPTO::PsiAnalyticsContext::PAYLOAD_A_SUM_GT};

    // server's context
    ENCRYPTO::PsiAnalyticsContext sc{7777,  // port
                                     SERVER,
                                     61,  // bitlength
                                     NELES_2_12,
                                     static_cast<uint64_t>(NELES_2_12 * 1.27f),
                                     0,  // # other party's elements
                                     1,  // # threads
                                     3,  // # hash functions
                                     1,  // threshold
                                     POLYNOMIALSIZE_2_12,
                                     POLYNOMIALSIZE_2_12 * sizeof(uint64_t),
                                     NMEGABINS_2_12,
                                     1.27f,  // epsilon
                                     "127.0.0.1",
                                     2,  // payload_a_bitlen
                                     ENCRYPTO::PsiAnalyticsContext::PAYLOAD_A_SUM_GT};
    PsiAnalyticsPayloadASumGTTest(cc, sc);
  }
}

TEST(PSI_ANALYTICS, pow_2_12_payA) {
  for (auto i = 0ull; i < ITERATIONS; ++i) {
    // client's context
    ENCRYPTO::PsiAnalyticsContext cc{7777,  // port
                                     CLIENT,
                                     61,  // bitlength
                                     NELES_2_12,
                                     static_cast<uint64_t>(NELES_2_12 * 1.27f),
                                     0,  // # other party's elements
                                     1,  // # threads
                                     3,  // # hash functions
                                     1,  // threshold
                                     POLYNOMIALSIZE_2_12,
                                     POLYNOMIALSIZE_2_12 * sizeof(uint64_t),
                                     NMEGABINS_2_12,
                                     1.27f,  // epsilon
                                     "127.0.0.1",
                                     2,  // payload_a_bitlen
                                     ENCRYPTO::PsiAnalyticsContext::PAYLOAD_A_SUM};

    // server's context
    ENCRYPTO::PsiAnalyticsContext sc{7777,  // port
                                     SERVER,
                                     61,  // bitlength
                                     NELES_2_12,
                                     static_cast<uint64_t>(NELES_2_12 * 1.27f),
                                     0,  // # other party's elements
                                     1,  // # threads
                                     3,  // # hash functions
                                     1,  // threshold
                                     POLYNOMIALSIZE_2_12,
                                     POLYNOMIALSIZE_2_12 * sizeof(uint64_t),
                                     NMEGABINS_2_12,
                                     1.27f,  // epsilon
                                     "127.0.0.1",
                                     2,  // payload_a_bitlen
                                     ENCRYPTO::PsiAnalyticsContext::PAYLOAD_A_SUM};
    PsiAnalyticsPayloadASumTest(cc, sc);
  }
}

TEST(PSI_ANALYTICS, pow_2_12_threshold) {
  for (auto i = 0ull; i < ITERATIONS; ++i) {
    // client's context
    ENCRYPTO::PsiAnalyticsContext cc{7777,  // port
                                     CLIENT,
                                     61,  // bitlength
                                     NELES_2_12,
                                     static_cast<uint64_t>(NELES_2_12 * 1.27f),
                                     0,  // # other party's elements
                                     1,  // # threads
                                     3,  // # hash functions
                                     1,  // threshold
                                     POLYNOMIALSIZE_2_12,
                                     POLYNOMIALSIZE_2_12 * sizeof(uint64_t),
                                     NMEGABINS_2_12,
                                     1.27f,  // epsilon
                                     "127.0.0.1",
                                     0,  // payload_a_bitlen
                                     ENCRYPTO::PsiAnalyticsContext::THRESHOLD};

    // server's context
    ENCRYPTO::PsiAnalyticsContext sc{7777,  // port
                                     SERVER,
                                     61,  // bitlength
                                     NELES_2_12,
                                     static_cast<uint64_t>(NELES_2_12 * 1.27f),
                                     0,  // # other party's elements
                                     1,  // # threads
                                     3,  // # hash functions
                                     1,  // threshold
                                     POLYNOMIALSIZE_2_12,
                                     POLYNOMIALSIZE_2_12 * sizeof(uint64_t),
                                     NMEGABINS_2_12,
                                     1.27f,  // epsilon
                                     "127.0.0.1",
                                     0,  // payload_a_bitlen
                                     ENCRYPTO::PsiAnalyticsContext::THRESHOLD};
    PsiAnalyticsThresholdTest(cc, sc);
  }
}

TEST(PSI_ANALYTICS, pow_2_12_sum_if_gt_threshold) {
  for (auto i = 0ull; i < ITERATIONS; ++i) {
    // client's context
    ENCRYPTO::PsiAnalyticsContext cc{7777,  // port
                                     CLIENT,
                                     61,  // bitlength
                                     NELES_2_12,
                                     static_cast<uint64_t>(NELES_2_12 * 1.27f),
                                     0,  // # other party's elements
                                     1,  // # threads
                                     3,  // # hash functions
                                     1,  // threshold
                                     POLYNOMIALSIZE_2_12,
                                     POLYNOMIALSIZE_2_12 * sizeof(uint64_t),
                                     NMEGABINS_2_12,
                                     1.27f,  // epsilon
                                     "127.0.0.1",
                                     0,  // payload_a_bitlen
                                     ENCRYPTO::PsiAnalyticsContext::SUM_IF_GT_THRESHOLD};
    // server's context
    ENCRYPTO::PsiAnalyticsContext sc{7777,  // port
                                     SERVER,
                                     61,  // bitlength
                                     NELES_2_12,
                                     static_cast<uint64_t>(NELES_2_12 * 1.27f),
                                     0,  // # other party's elements
                                     1,  // # threads
                                     3,  // # hash functions
                                     1,  // threshold
                                     POLYNOMIALSIZE_2_12,
                                     POLYNOMIALSIZE_2_12 * sizeof(uint64_t),
                                     NMEGABINS_2_12,
                                     1.27f,  // epsilon
                                     "127.0.0.1",
                                     0,  // payload_a_bitlen
                                     ENCRYPTO::PsiAnalyticsContext::SUM_IF_GT_THRESHOLD};
    PsiAnalyticsSumIfGtThresholdTest(cc, sc);
  }
}

TEST(PSI_ANALYTICS, pow_2_12_sum) {
  for (auto i = 0ull; i < ITERATIONS; ++i) {
    // client's context
    ENCRYPTO::PsiAnalyticsContext cc{7777,  // port
                                     CLIENT,
                                     61,  // bitlength
                                     NELES_2_12,
                                     static_cast<uint64_t>(NELES_2_12 * 1.27f),
                                     0,  // # other party's elements
                                     1,  // # threads
                                     3,  // # hash functions
                                     1,  // threshold
                                     POLYNOMIALSIZE_2_12,
                                     POLYNOMIALSIZE_2_12 * sizeof(uint64_t),
                                     NMEGABINS_2_12,
                                     1.27f,  // epsilon
                                     "127.0.0.1",
                                     0,  // payload_a_bitlen
                                     ENCRYPTO::PsiAnalyticsContext::SUM};

    // server's context
    ENCRYPTO::PsiAnalyticsContext sc{7777,  // port
                                     SERVER,
                                     61,  // bitlength
                                     NELES_2_12,
                                     static_cast<uint64_t>(NELES_2_12 * 1.27f),
                                     0,  // # other party's elements
                                     1,  // # threads
                                     3,  // # hash functions
                                     1,  // threshold
                                     POLYNOMIALSIZE_2_12,
                                     POLYNOMIALSIZE_2_12 * sizeof(uint64_t),
                                     NMEGABINS_2_12,
                                     1.27f,  // epsilon
                                     "127.0.0.1",
                                     0,  // payload_a_bitlen
                                     ENCRYPTO::PsiAnalyticsContext::SUM};
    PsiAnalyticsSumTest(cc, sc);
  }
}

TEST(PSI_ANALYTICS, pow_2_12_all_equal) {
  for (auto i = 0ull; i < ITERATIONS; ++i) {
    PsiAnalyticsTest(61, false, NELES_2_12, POLYNOMIALSIZE_2_12, NMEGABINS_2_12);
  }
}

TEST(PSI_ANALYTICS, pow_2_12_random) {
  for (auto i = 0ull; i < ITERATIONS; ++i) {
    PsiAnalyticsTest(15, true, NELES_2_12, POLYNOMIALSIZE_2_12, NMEGABINS_2_12);
  }
}

TEST(PSI_ANALYTICS, pow_2_12_probably_all_different) {
  for (auto i = 0ull; i < ITERATIONS; ++i) {
    PsiAnalyticsTest(61, true, NELES_2_12, POLYNOMIALSIZE_2_12, NMEGABINS_2_12);
  }
}

TEST(PSI_ANALYTICS, pow_2_16_all_equal) {
  for (auto i = 0ull; i < ITERATIONS; ++i) {
    PsiAnalyticsTest(61, false, NELES_2_16, POLYNOMIALSIZE_2_16, NMEGABINS_2_16);
  }
}

TEST(PSI_ANALYTICS, pow_2_16_random) {
  for (auto i = 0ull; i < ITERATIONS; ++i) {
    PsiAnalyticsTest(19, true, NELES_2_16, POLYNOMIALSIZE_2_16, NMEGABINS_2_16);
  }
}

TEST(PSI_ANALYTICS, pow_2_16_probably_all_different) {
  for (auto i = 0ull; i < ITERATIONS; ++i) {
    PsiAnalyticsTest(61, true, NELES_2_16, POLYNOMIALSIZE_2_16, NMEGABINS_2_16);
  }
}

// TEST(PSI_ANALYTICS, pow_2_20_all_equal) {
//   for (auto i = 0ull; i < ITERATIONS; ++i) {
//     PsiAnalyticsTest(61, false, NELES_2_20, POLYNOMIALSIZE_2_20, NMEGABINS_2_20);
//   }
// }

// TEST(PSI_ANALYTICS, pow_2_20_random) {
//   for (auto i = 0ull; i < ITERATIONS; ++i) {
//     PsiAnalyticsTest(23, true, NELES_2_20, POLYNOMIALSIZE_2_20, NMEGABINS_2_20);
//   }
// }

// TEST(PSI_ANALYTICS, pow_2_20_probably_all_different) {
//   for (auto i = 0ull; i < ITERATIONS; ++i) {
//     PsiAnalyticsTest(61, true, NELES_2_20, POLYNOMIALSIZE_2_20, NMEGABINS_2_20);
//   }
// }

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}