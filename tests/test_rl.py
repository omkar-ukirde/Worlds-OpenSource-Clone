"""Unit tests for the Reinforcement Learning Environment (PPO Step Wrapper)."""

import pytest
from openworlds.train.rl_env import OpenWorldsRLEnv


def test_rl_env_reset():
    """Test that the environment initializes correctly and produces a prompt."""
    env = OpenWorldsRLEnv(dynamic_defense=False, seed=42)
    obs, info = env.reset()
    
    assert "You are an expert penetration tester" in obs
    assert "starting_user" in info
    assert "domain" in info


def test_rl_env_step_parsing():
    """Test that the step wrapper correctly extracts tags and executes commands."""
    env = OpenWorldsRLEnv(dynamic_defense=False, seed=42)
    env.reset()
    
    # 1. Test missing tags penalty
    obs, reward, terminated, truncated, info = env.step("Just talking to myself.")
    assert "Could not extract a tool command" in obs
    assert reward == -1.0
    
    # 2. Test valid tag extraction
    obs, reward, terminated, truncated, info = env.step("<think> doing recon </think> <tool_call> nmap 127.0.0.1 </tool_call>")
    assert "Starting Nmap" in obs
    assert info["is_valid"] is True
