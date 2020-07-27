defmodule WebAuthTest do
  use ExUnit.Case
  doctest WebAuth

  test "greets the world" do
    assert WebAuth.hello() == :world
  end
end
