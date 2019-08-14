#ifndef TANKER_FAKE_AUTHENTICATION_C_H
#define TANKER_FAKE_AUTHENTICATION_C_H

#include <ctanker/async.h>
#include <ctanker/fakeauthentication/export.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tanker_fake_authentication tanker_fake_authentication_t;
typedef struct tanker_fake_authentication_private_identity
    tanker_fake_authentication_private_identity_t;
typedef struct tanker_fake_authentication_options
    tanker_fake_authentication_options_t;
typedef struct tanker_fake_authentication_public_identities
    tanker_fake_authentication_public_identities_t;

struct tanker_fake_authentication_options
{
  uint8_t version;
  char const* url;
  char const* app_id;
};

#define TANKER_FAKE_AUTHENTICATION_OPTIONS_INIT \
  {                                             \
    1, NULL, NULL                               \
  }

struct tanker_fake_authentication_private_identity
{
  char const* permanent_identity;
  char const* provisional_identity;
};

struct tanker_fake_authentication_public_identities
{
  char const* const* public_identities;
  uint64_t nb_public_identities;
};

/*!
 * Creates a tanker fake authentication instance.
 * \param options the options for fake authentication creation
 * \pre the *options* must not be NULL, as well as the field *app_id*.
 * \return A tanker_future of a tanker_fake_authentication_t*.
 * \throws TANKER_ERROR_INVALID_ARGUMENT \p options is NULL, or lacks
 * mandatory fields.
 */
TANKER_FAKE_AUTHENTICATION_C_EXPORT tanker_expected_t*
tanker_fake_authentication_create(
    tanker_fake_authentication_options_t const* options);

/*! Destroy a tanker fakeauthentication instance.
 * \param fake_auth the fake authentication to be deleted.
 */
TANKER_FAKE_AUTHENTICATION_C_EXPORT tanker_future_t*
tanker_fake_authentication_destroy(tanker_fake_authentication_t* fake_auth);

/*! Create and retrieve a tanker private a identities from an email.
 * \param fake_auth A tanker_fake_authentication_t* instance.
 * \param email a valid email.
 * \returns a tanker_future of a tanker_fake_authentication_private_identity_t*.
 *  This must be freed with
 * tanker_fake_authentication_destroy_private_identity().
 */
TANKER_FAKE_AUTHENTICATION_C_EXPORT tanker_future_t*
tanker_fake_authentication_get_private_identity(
    tanker_fake_authentication_t* fake_auth, char const* email);

/*! Retrieve the tanker public identities from an email list.
 * \param fake_auth A tanker_fake_authentication_t* instance.
 * \param emails a list of emails.
 * \param nb_emails number of emails provided.
 * \returns a tanker_future of a
 * tanker_fake_authentication_public_identities_t*. This must be freed with
 * tanker_fake_authentication_destroy_public_identities().
 */
TANKER_FAKE_AUTHENTICATION_C_EXPORT tanker_future_t*
tanker_fake_authentication_get_public_identities(
    tanker_fake_authentication_t* fake_auth,
    char const* const* emails,
    uint64_t nb_emails);

TANKER_FAKE_AUTHENTICATION_C_EXPORT void
tanker_fake_authentication_destroy_private_identity(
    tanker_fake_authentication_private_identity_t*);

TANKER_FAKE_AUTHENTICATION_C_EXPORT void
tanker_fake_authentication_destroy_public_identities(
    tanker_fake_authentication_public_identities_t*);

#ifdef __cplusplus
}
#endif

#endif
