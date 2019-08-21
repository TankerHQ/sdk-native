#ifndef TANKER_ASYNC_C_H
#define TANKER_ASYNC_C_H

#include <stdbool.h>

#include <ctanker/async/error.h>
#include <ctanker/async/export.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tanker_future tanker_future_t;
typedef struct tanker_future tanker_expected_t;
typedef struct tanker_promise tanker_promise_t;
typedef struct tanker_error tanker_error_t;

typedef void* (*tanker_future_then_t)(tanker_future_t* fut, void* arg);

/*!
 * Create a new empty promise.
 * \remark must call tanker_promise_destroy() to get rid of it.
 */
TANKER_ASYNC_EXPORT tanker_promise_t* tanker_promise_create(void);

/*!
 * Destroy a promise.
 * \pre promise must be allocated with tanker_promise_create().
 */
TANKER_ASYNC_EXPORT void tanker_promise_destroy(tanker_promise_t* promise);

/*!
 * Get a future from a promise.
 * \pre promise parameter must be allocated with tanker_promise_create().
 * \remark must call tanker_future_destroy"()" to get rid of the returned
 *         future.
 */
TANKER_ASYNC_EXPORT tanker_future_t* tanker_promise_get_future(
    tanker_promise_t* promise);

/*!
 * Set a promise value.
 * \pre promise parameter must be allocated with tanker_promise_create().
 */
TANKER_ASYNC_EXPORT void tanker_promise_set_value(tanker_promise_t* promise,
                                                    void* value);

/*!
 * Get the content of the future.
 * \return The void pointer representing the value. Refer to the documentation
 * of the function returning the future to know how to interpret the value.
 */
TANKER_ASYNC_EXPORT void* tanker_future_get_voidptr(tanker_future_t* future);

/*!
 * Returns 1 if the future is ready, 0 otherwise.
 */
TANKER_ASYNC_EXPORT bool tanker_future_is_ready(tanker_future_t* future);

/*!
 * Block until the future is ready.
 * \pre future parameter must be allocated with tanker API.
 */
TANKER_ASYNC_EXPORT void tanker_future_wait(tanker_future_t* future);

/*!
 * Set a callback to the future chain.
 * \remark For the moment adding multiple callbacks is undefined
 * \param arg arguments for the callback.
 * \return A new future with the callback.
 * \remark The future returned has to be freed with tanker_future_destroy().
 */
TANKER_ASYNC_EXPORT tanker_future_t* tanker_future_then(
    tanker_future_t* future, tanker_future_then_t cb, void* arg);

/*!
 * Get the future error if any.
 *
 * \return The error contained in the future or NULL if there was no error.
 */
TANKER_ASYNC_EXPORT tanker_error_t* tanker_future_get_error(
    tanker_future_t* future);

/*!
 * Check if there is an error in the future.
 *
 * \return 0 if the future has no error, any other value otherwise.
 */
TANKER_ASYNC_EXPORT unsigned char tanker_future_has_error(
    tanker_future_t* future);

TANKER_ASYNC_EXPORT void tanker_future_destroy(tanker_future_t* future);

#ifdef __cplusplus
}
#endif

#endif
