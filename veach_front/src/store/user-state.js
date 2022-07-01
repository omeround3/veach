import { createStore } from "vuex";

export default createStore({
    state: {
        username: "",
        password: "",
        token: null,
        loggenIn: false,
    
    },
    mutations: {
      setUser(state, user) {
        state.username = user
      },
      setPassword(state, pass) {
        state.password = pass
      },
      setToken(state, token) {
        state.token = token
      }
    },
    // actions: {
     
    // },
    // getters: {},
  });
  