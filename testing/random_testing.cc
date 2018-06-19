// Program to perform random actions in a network of toxes.
//
// Useful to find reproducing test cases for seemingly random bugs.

#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <memory>
#include <random>
#include <vector>

#include "../toxcore/tox.h"
#include "misc_tools.c"

namespace {

// Whether to write log messages when handling callbacks.
constexpr bool LOG_CALLBACKS = 0;

// Number of participants in the test run.
constexpr uint32_t NUM_TOXES = 10;
// Maximum amount of time in iterations to wait for bootstrapping and friend
// connections to succeed.
constexpr uint32_t MAX_BOOTSTRAP_ITERATIONS = 1000;
// Number of conferences up to which users may create their own new conferences.
// They may still be invited and join.
constexpr uint32_t MAX_CONFERENCES_PER_USER = 3;
// Maximum number of actions per program execution.
constexpr uint32_t MAX_ACTIONS = 10000;
// Maximum number of attempts at executing a random action.
constexpr uint32_t MAX_ACTION_ATTEMPTS = 100;
// Number of tox_iterate calls between each action.
constexpr uint32_t ITERATIONS_PER_ACTION = 1;
// Amount of time in milliseconds to wait between tox_iterate calls.
constexpr uint32_t ITERATION_INTERVAL = 5;

struct Tox_Options_Deleter {
  void operator()(Tox_Options *options) const { tox_options_free(options); }
};

using Tox_Options_Ptr = std::unique_ptr<Tox_Options, Tox_Options_Deleter>;

struct Tox_Deleter {
  void operator()(Tox *tox) const { tox_kill(tox); }
};

using Tox_Ptr = std::unique_ptr<Tox, Tox_Deleter>;

struct Local_State {
  Tox_Ptr tox;

  uint32_t friends_online = 0;
  uint32_t next_invite = 0;

  explicit Local_State(Tox_Ptr tox, uint32_t id)
      : tox(std::move(tox)),
        id_(id) {}

  uint32_t id() const { return id_; }

 private:
  uint32_t id_;
};

struct Random {
  std::uniform_int_distribution<> tox_selector;
  std::uniform_int_distribution<> friend_selector;
  std::uniform_int_distribution<> name_length_selector;
  std::uniform_int_distribution<> message_length_selector;
  std::uniform_int_distribution<> byte_selector;

  std::vector<size_t> action_weights;
  std::discrete_distribution<size_t> action_selector;

  Random();
};

struct Action {
  uint32_t weight;
  char const *title;
  bool (*can)(Local_State const &state);
  void (*run)(Local_State &state, Random &rnd, std::mt19937 &rng);
};

Action const actions[] = {
    {
        10,
        "creates a new conference",
        [](Local_State const &state) {
          return tox_conference_get_chatlist_size(state.tox.get()) < MAX_CONFERENCES_PER_USER;
        },
        [](Local_State &state, Random &rnd, std::mt19937 &rng) {
          TOX_ERR_CONFERENCE_NEW err;
          tox_conference_new(state.tox.get(), &err);
          assert(err == TOX_ERR_CONFERENCE_NEW_OK);
        },
    },
    {
        10,
        "invites a random friend to a conference",
        [](Local_State const &state) {
          return tox_conference_get_chatlist_size(state.tox.get()) != 0;
        },
        [](Local_State &state, Random &rnd, std::mt19937 &rng) {
          TOX_ERR_CONFERENCE_INVITE err;
          tox_conference_invite(
              state.tox.get(), rnd.friend_selector(rng),
              state.next_invite % tox_conference_get_chatlist_size(state.tox.get()), &err);
          state.next_invite++;
          assert(err == TOX_ERR_CONFERENCE_INVITE_OK);
        },
    },
    {
        10,
        "deletes the last conference",
        [](Local_State const &state) {
          return tox_conference_get_chatlist_size(state.tox.get()) != 0;
        },
        [](Local_State &state, Random &rnd, std::mt19937 &rng) {
          TOX_ERR_CONFERENCE_DELETE err;
          tox_conference_delete(state.tox.get(),
                                tox_conference_get_chatlist_size(state.tox.get()) - 1, &err);
          assert(err == TOX_ERR_CONFERENCE_DELETE_OK);
        },
    },
    {
        10,
        "sends a message to the last conference",
        [](Local_State const &state) {
          return tox_conference_get_chatlist_size(state.tox.get()) != 0;
        },
        [](Local_State &state, Random &rnd, std::mt19937 &rng) {
          std::vector<uint8_t> message(rnd.message_length_selector(rng));
          for (uint8_t &byte : message) {
            byte = rnd.byte_selector(rng);
          }

          TOX_ERR_CONFERENCE_SEND_MESSAGE err;
          tox_conference_send_message(
              state.tox.get(), tox_conference_get_chatlist_size(state.tox.get()) - 1,
              TOX_MESSAGE_TYPE_NORMAL, message.data(), message.size(), &err);
          if (err == TOX_ERR_CONFERENCE_SEND_MESSAGE_OK) {
            printf(" (OK, length = %u)", (unsigned)message.size());
          } else {
            printf(" (FAILED: %u)", err);
          }
        },
    },
    {
        10,
        "changes their name",
        [](Local_State const &state) { return true; },
        [](Local_State &state, Random &rnd, std::mt19937 &rng) {
          std::vector<uint8_t> name(rnd.name_length_selector(rng));
          for (uint8_t &byte : name) {
            byte = rnd.byte_selector(rng);
          }

          TOX_ERR_SET_INFO err;
          tox_self_set_name(state.tox.get(), name.data(), name.size(), &err);
          assert(err == TOX_ERR_SET_INFO_OK);

          printf(" (length = %u)", (unsigned)name.size());
        },
    },
    {
        10,
        "sets their name to empty",
        [](Local_State const &state) { return true; },
        [](Local_State &state, Random &rnd, std::mt19937 &rng) {
          TOX_ERR_SET_INFO err;
          tox_self_set_name(state.tox.get(), nullptr, 0, &err);
          assert(err == TOX_ERR_SET_INFO_OK);
        },
    },
};

std::vector<size_t> get_action_weights() {
  std::vector<size_t> weights;
  for (Action const &action : actions) {
    weights.push_back(action.weight);
  }
  return weights;
}

Random::Random()
    : tox_selector(0, NUM_TOXES - 1),
      friend_selector(0, NUM_TOXES - 2),
      name_length_selector(0, TOX_MAX_NAME_LENGTH - 1),
      message_length_selector(0, TOX_MAX_MESSAGE_LENGTH - 1),
      byte_selector(0, 255),
      action_weights(get_action_weights()),
      action_selector(action_weights.begin(), action_weights.end()) {}

struct Global_State : std::vector<Local_State> {
  // Non-copyable;
  Global_State(Global_State const &) = delete;
  Global_State(Global_State &&) = default;
  Global_State()
      : action_counter(rnd.action_weights.size()) {}

  Random rnd;
  std::vector<unsigned> action_counter;
};

void handle_friend_connection_status(Tox *tox, uint32_t friend_number,
                                     TOX_CONNECTION connection_status, void *user_data) {
  Local_State *state = static_cast<Local_State *>(user_data);

  if (connection_status == TOX_CONNECTION_NONE) {
    std::printf("Tox #%u lost friend %u!\n", state->id(), friend_number);
    state->friends_online--;
  } else {
    state->friends_online++;
  }
}

void handle_conference_invite(Tox *tox, uint32_t friend_number, TOX_CONFERENCE_TYPE type,
                              const uint8_t *cookie, size_t length, void *user_data) {
  Local_State *state = static_cast<Local_State *>(user_data);

  if (LOG_CALLBACKS) {
    std::printf("Tox #%u joins the conference it was invited to\n", state->id());
  }

  TOX_ERR_CONFERENCE_JOIN err;
  tox_conference_join(tox, friend_number, cookie, length, &err);
  assert(err == TOX_ERR_CONFERENCE_JOIN_OK);
}

void handle_conference_message(Tox *tox, uint32_t conference_number, uint32_t peer_number,
                               TOX_MESSAGE_TYPE type, const uint8_t *message, size_t length,
                               void *user_data) {
  Local_State *state = static_cast<Local_State *>(user_data);

  if (LOG_CALLBACKS) {
    std::printf("Tox #%u received a message of length %u\n", state->id(), (unsigned)length);
  }
}

void handle_conference_peer_list_changed(Tox *tox, uint32_t conference_number, void *user_data) {
  Local_State *state = static_cast<Local_State *>(user_data);

  if (LOG_CALLBACKS) {
    std::printf("Tox #%u rebuilds peer list for conference %u\n", state->id(), conference_number);
  }

  TOX_ERR_CONFERENCE_PEER_QUERY err;
  uint32_t const count = tox_conference_peer_count(tox, conference_number, &err);
  assert(err == TOX_ERR_CONFERENCE_PEER_QUERY_OK);

  for (uint32_t peer_number = 0; peer_number < count; peer_number++) {
    size_t size = tox_conference_peer_get_name_size(tox, conference_number, peer_number, &err);
    assert(err == TOX_ERR_CONFERENCE_PEER_QUERY_OK);

    std::vector<uint8_t> name(size);
    tox_conference_peer_get_name(tox, conference_number, peer_number, &name[0], &err);
    assert(err == TOX_ERR_CONFERENCE_PEER_QUERY_OK);
  }
}

Global_State make_toxes() {
  Global_State toxes;

  Tox_Options_Ptr options(tox_options_new(nullptr));
  tox_options_set_local_discovery_enabled(options.get(), false);

  for (uint32_t i = 0; i < NUM_TOXES; i++) {
    TOX_ERR_NEW err;
    toxes.emplace_back(Tox_Ptr(tox_new(options.get(), &err)), i);
    assert(err == TOX_ERR_NEW_OK);
    assert(toxes.back().tox != nullptr);

    tox_callback_friend_connection_status(toxes.back().tox.get(), handle_friend_connection_status);
    tox_callback_conference_invite(toxes.back().tox.get(), handle_conference_invite);
    tox_callback_conference_message(toxes.back().tox.get(), handle_conference_message);
    tox_callback_conference_peer_list_changed(toxes.back().tox.get(),
                                              handle_conference_peer_list_changed);
  }

  std::printf("Bootstrapping %u toxes\n", NUM_TOXES);

  uint8_t dht_key[TOX_PUBLIC_KEY_SIZE];
  tox_self_get_dht_id(toxes.front().tox.get(), dht_key);
  const uint16_t dht_port = tox_self_get_udp_port(toxes.front().tox.get(), nullptr);

  for (Local_State const &state : toxes) {
    TOX_ERR_BOOTSTRAP err;
    tox_bootstrap(state.tox.get(), "localhost", dht_port, dht_key, &err);
    assert(err == TOX_ERR_BOOTSTRAP_OK);
  }

  std::printf("Creating full mesh of friendships\n");

  for (Local_State const &state1 : toxes) {
    for (Local_State const &state2 : toxes) {
      if (state1.tox != state2.tox) {
        TOX_ERR_FRIEND_ADD err;
        uint8_t key[TOX_PUBLIC_KEY_SIZE];

        tox_self_get_public_key(state1.tox.get(), key);
        tox_friend_add_norequest(state2.tox.get(), key, &err);
        assert(err == TOX_ERR_FRIEND_ADD_OK);
      }
    }
  }

  return toxes;
}

bool all_connected(Global_State const &toxes) {
  return std::all_of(toxes.begin(), toxes.end(), [](Local_State const &state) {
    return state.friends_online == NUM_TOXES - 1;
  });
}

bool bootstrap_toxes(Global_State &toxes) {
  std::printf("Waiting for %u iterations for all friends to come online\n",
              MAX_BOOTSTRAP_ITERATIONS);

  for (uint32_t i = 0; i < MAX_BOOTSTRAP_ITERATIONS; i++) {
    c_sleep(tox_iteration_interval(toxes.front().tox.get()));

    for (Local_State &state : toxes) {
      tox_iterate(state.tox.get(), &state);
    }

    if (all_connected(toxes)) {
      std::printf("Took %u iterations\n", i);
      return true;
    }
  }

  return false;
}

bool execute_random_action(Global_State &toxes, std::mt19937 &rng) {
  // First, choose a random actor.
  Local_State &actor = toxes.at(toxes.rnd.tox_selector(rng));
  size_t const action_id = toxes.rnd.action_selector(rng);
  Action const &action = actions[action_id];
  if (!action.can(actor)) {
    return false;
  }

  std::printf("Tox #%u %s", actor.id(), action.title);
  action.run(actor, toxes.rnd, rng);
  std::printf("\n");

  toxes.action_counter.at(action_id)++;

  return true;
}

bool attempt_action(Global_State &toxes, std::mt19937 &rng) {
  for (uint32_t i = 0; i < MAX_ACTION_ATTEMPTS; i++) {
    if (execute_random_action(toxes, rng)) {
      return true;
    }
  }

  return false;
}

}  // namespace

int main() {
  Global_State toxes = make_toxes();

  std::mt19937 rng;
  uint32_t action_number;
  for (action_number = 0; action_number < MAX_ACTIONS; action_number++) {
    if (!all_connected(toxes)) {
      if (!bootstrap_toxes(toxes)) {
        std::printf("Bootstrapping took too long; %u actions performed\n", action_number);
        return EXIT_FAILURE;
      }
    }

    if (!attempt_action(toxes, rng)) {
      std::printf("System is stuck after %u actions: none of the toxes can perform an action anymore\n",
                  action_number);
      return EXIT_FAILURE;
    }

    for (uint32_t i = 0; i < ITERATIONS_PER_ACTION; i++) {
      c_sleep(ITERATION_INTERVAL);

      for (Local_State &state : toxes) {
        tox_iterate(state.tox.get(), &state);
      }
    }
  }

  std::printf("Test execution success: %u actions performed\n", action_number);
  std::printf("Per-action statistics:\n");
  for (uint32_t i = 0; i < toxes.action_counter.size(); i++) {
    std::printf("%u x '%s'\n", toxes.action_counter.at(i), actions[i].title);
  }
}
