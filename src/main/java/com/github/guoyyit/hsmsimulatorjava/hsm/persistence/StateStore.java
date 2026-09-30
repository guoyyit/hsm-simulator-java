package com.github.guoyyit.hsmsimulatorjava.hsm.persistence;

import com.github.guoyyit.hsmsimulatorjava.hsm.TokenState;

public interface StateStore {

    TokenState load();

    void save(TokenState state);
}
