#pragma once
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

#include "abycore/aby/abyparty.h"
#include "abycore/circuit/share.h"
#include "abycore/sharing/arithsharing.h"
#include "abycore/sharing/boolsharing.h"
#include "helpers.h"
#include "psi_analytics_context.h"

#include <vector>

namespace ENCRYPTO {

uint64_t run_psi_analytics(const std::vector<std::uint64_t> &inputs, PsiAnalyticsContext &context);

uint64_t run_psi_analytics(const std::vector<std::uint64_t> &inputs, PsiAnalyticsContext &context,
                           const std::vector<std::uint64_t> &payload_input_a);

uint64_t run_psi_analytics(const std::vector<std::uint64_t> &inputs, PsiAnalyticsContext &context,
                             const std::vector<std::uint64_t> &payload_input_a,
                             const std::vector<std::uint64_t> &payload_input_b);

uint64_t run_psi_analyticsAB(const std::vector<std::uint64_t> &inputs, PsiAnalyticsContext &context,
                             const std::vector<std::uint64_t> &payload_input_a,
                             const std::vector<std::uint64_t> &payload_input_b);

std::shared_ptr<share> BuildIntersectionSumHamming(std::shared_ptr<share> s_payload,
                                                   std::shared_ptr<share> s_eq, BooleanCircuit *bc);
std::shared_ptr<share> BuildIntersectionSum(std::shared_ptr<share> s_payload,
                                            std::shared_ptr<share> s_eq, BooleanCircuit *bc,
                                            ArithmeticCircuit *ac);
std::shared_ptr<share> BuildGreaterThan(std::shared_ptr<share> s_in,
                                        std::shared_ptr<share> s_threshold,
                                        std::shared_ptr<share> s_zero, BooleanCircuit *circ);
std::shared_ptr<share> BuildSum(std::shared_ptr<share> s_a, ArithmeticCircuit *ac);

std::vector<std::pair<uint64_t, uint64_t>> OpprgPsiClient(const std::vector<uint64_t> &elements,
                                                          PsiAnalyticsContext &context);

std::vector<uint64_t> OpprgPsiServer(const std::vector<uint64_t> &elements,
                                     PsiAnalyticsContext &context);

std::vector<std::pair<uint64_t, uint64_t>> OpprgPsiClientAB(const std::vector<uint64_t> &elements,
                                                            PsiAnalyticsContext &context,
                                                            std::vector<uint64_t> &index);

std::vector<std::pair<uint64_t, uint64_t>> OpprgPsiServerAB(
    const std::vector<uint64_t> &elements, PsiAnalyticsContext &context,
    const std::vector<std::uint64_t> &payload_input_b);

void InterpolatePolynomials(std::vector<uint64_t> &polynomials,
                            std::vector<uint64_t> &content_of_bins,
                            const std::vector<std::vector<uint64_t>> &masks,
                            PsiAnalyticsContext &context);

void InterpolatePolynomials(std::vector<uint64_t> &polynomials,
                            std::vector<std::vector<uint64_t>> &contents_of_bins,
                            const std::vector<std::vector<uint64_t>> &masks,
                            PsiAnalyticsContext &context);

void InterpolatePolynomialsPaddedWithDummies(
    std::vector<uint64_t>::iterator polynomial_offset,
    std::vector<std::vector<uint64_t>>::const_iterator random_value_in_bin,
    std::vector<std::vector<uint64_t>>::const_iterator masks_for_elems_in_bin,
    std::size_t nbins_in_megabin, PsiAnalyticsContext &context);

std::unique_ptr<CSocket> EstablishConnection(const std::string &address, uint16_t port,
                                             e_role role);

std::size_t PlainIntersectionSize(std::vector<std::uint64_t> v1, std::vector<std::uint64_t> v2);

void PrintTimings(const PsiAnalyticsContext &context);
}  // namespace ENCRYPTO