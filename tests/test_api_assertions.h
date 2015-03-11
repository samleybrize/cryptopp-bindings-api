/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef TEST_API_CRYPTOPP_ASSERTIONS_H
#define TEST_API_CRYPTOPP_ASSERTIONS_H

#include "src/api_cryptopp.h"
#include <gtest/gtest.h>
#include <string>

// byte array comparison
#define EXPECT_BYTE_ARRAY_EQ(expected, expectedSize, actual, actualSize) GTEST_ASSERT_(ByteArrayEquals(expected, expectedSize, actual, actualSize), GTEST_NONFATAL_FAILURE_);
#define EXPECT_BYTE_ARRAY_NE(notExpected, expectedSize, actual, actualSize) GTEST_ASSERT_(ByteArrayNotEquals(notExpected, expectedSize, actual, actualSize), GTEST_NONFATAL_FAILURE_);
#define ASSERT_BYTE_ARRAY_EQ(expected, expectedSize, actual, actualSize) GTEST_ASSERT_(ByteArrayEquals(expected, expectedSize, actual, actualSize), GTEST_FATAL_FAILURE_);
#define ASSERT_BYTE_ARRAY_NE(notExpected, expectedSize, actual, actualSize) GTEST_ASSERT_(ByteArrayNotEquals(notExpected, expectedSize, actual, actualSize), GTEST_FATAL_FAILURE_);

::testing::AssertionResult ByteArrayEquals(const byte *expected, const size_t expectedSize, const byte *actual, const size_t actualSize);
::testing::AssertionResult ByteArrayNotEquals(const byte *expected, const size_t expectedSize, const byte *actual, const size_t actualSize);

// exception message test
#define EXPECT_THROW_MSG(statement, expected_exception, msg) \
    TEST_THROW_MSG_(statement, expected_exception, msg, GTEST_NONFATAL_FAILURE_)
#define ASSERT_THROW_MSG(statement, expected_exception, msg) \
    TEST_THROW_MSG_(statement, expected_exception, msg, GTEST_FATAL_FAILURE_)

#define TEST_THROW_MSG_(statement, expected_exception, expected_msg, fail) \
    GTEST_AMBIGUOUS_ELSE_BLOCKER_ \
    if (::testing::internal::ConstCharPtr gtest_msg = "") { \
        bool gtest_caught_expected = false; \
        try { \
            GTEST_SUPPRESS_UNREACHABLE_CODE_WARNING_BELOW_(statement); \
        } catch (expected_exception const&e) { \
            gtest_caught_expected = true; \
            if (0 != strcmp(expected_msg, e.what())) { \
                std::string msg("Expected: " #statement " throws an exception of type " #expected_exception " with message '"); \
                msg.append(expected_msg); \
                msg.append("'.\n"); \
                msg.append("  Actual: message is '"); \
                msg.append(e.what()); \
                msg.append("'."); \
                /* using the label cause the first message to not appear. This is a workaround */ \
                fail(msg.c_str()); \
                break; \
            } \
        } catch (...) { \
            gtest_msg.value = \
                "Expected: " #statement " throws an exception of type " \
                #expected_exception ".\n  Actual: it throws a different type."; \
            goto GTEST_CONCAT_TOKEN_(gtest_label_testthrow_, __LINE__); \
        } \
        if (!gtest_caught_expected) { \
            gtest_msg.value = \
                "Expected: " #statement " throws an exception of type " \
                #expected_exception ".\n  Actual: it throws nothing."; \
            goto GTEST_CONCAT_TOKEN_(gtest_label_testthrow_, __LINE__); \
        } \
    } else \
        GTEST_CONCAT_TOKEN_(gtest_label_testthrow_, __LINE__): \
            fail(gtest_msg.value)

#endif /* TEST_API_CRYPTOPP_ASSERTIONS_H */
