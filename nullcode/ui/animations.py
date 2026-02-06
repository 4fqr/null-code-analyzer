"""
Animations for NULL-CODE-ANALYZER
High-precision character-based animations with black/white aesthetic
"""

import time
import sys
from typing import Iterator
from rich.console import Console
from rich.live import Live
from rich.text import Text
from .themes import WAVE_CHARS, PULSE_CHARS, LOGO, BOX_HORIZONTAL


class Animations:
    """Manages all CLI animations"""

    def __init__(self, console: Console):
        self.console = console

    def typewriter_logo(self, delay: float = 0.05) -> None:
        """
        Display logo with character-by-character typewriter effect
        
        Args:
            delay: Delay between characters in seconds (default: 50ms)
        """
        for char in LOGO:
            sys.stdout.write(char)
            sys.stdout.flush()
            if char != "\n":
                time.sleep(delay)
        print()  # Final newline

    def wave_progress(self, total: int, description: str = "Scanning") -> Iterator[int]:
        """
        Flowing wave progress animation (░▒▓█▓▒░)
        
        Args:
            total: Total number of items to process
            description: Description text for progress
            
        Yields:
            Current progress count
        """
        wave_position = 0
        
        with Live(console=self.console, refresh_per_second=10) as live:
            for current in range(total):
                # Generate wave pattern
                wave_display = self._generate_wave(current, total, wave_position)
                percentage = (current + 1) / total * 100
                
                # Build display text
                display = Text()
                display.append(f"{description}: ", style="white")
                display.append(wave_display, style="bright_black")
                display.append(f" {percentage:5.1f}% ", style="white")
                display.append(f"({current + 1}/{total})", style="bright_black")
                
                live.update(display)
                wave_position = (wave_position + 1) % len(WAVE_CHARS)
                
                yield current + 1
                time.sleep(0.01)  # Small delay for visual effect

    def _generate_wave(self, current: int, total: int, wave_pos: int) -> str:
        """Generate the wave pattern for progress bar"""
        bar_width = 40
        filled = int(bar_width * current / total)
        
        wave = []
        for i in range(bar_width):
            if i < filled:
                # Completed portion with wave effect
                char_idx = (i + wave_pos) % len(WAVE_CHARS)
                wave.append(WAVE_CHARS[char_idx])
            else:
                # Empty portion
                wave.append("░")
        
        return "".join(wave)

    def pulsing_highlight(self, text: str, pulses: int = 3) -> None:
        """
        Subtle pulsing effect by alternating █/▒
        
        Args:
            text: Text to pulse
            pulses: Number of pulse cycles
        """
        with Live(console=self.console, refresh_per_second=4) as live:
            for _ in range(pulses * 2):
                for char in PULSE_CHARS:
                    display = Text()
                    display.append(f"{char} ", style="white")
                    display.append(text, style="white")
                    display.append(f" {char}", style="white")
                    live.update(display)
                    time.sleep(0.25)

    def spinner(self, text: str = "Processing") -> Iterator[None]:
        """
        Simple text-based spinner (for backwards compatibility)
        
        Args:
            text: Text to display with spinner
        """
        frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        frame_idx = 0
        
        with Live(console=self.console, refresh_per_second=10) as live:
            while True:
                display = Text()
                display.append(f"{frames[frame_idx]} ", style="bright_black")
                display.append(text, style="white")
                live.update(display)
                
                frame_idx = (frame_idx + 1) % len(frames)
                yield
                time.sleep(0.1)

    def draw_box(self, content: str, width: int = 80) -> None:
        """
        Draw a box around content using box-drawing characters
        
        Args:
            content: Text content to box
            width: Box width in characters
        """
        lines = content.split("\n")
        
        # Top border
        self.console.print("┌" + BOX_HORIZONTAL * (width - 2) + "┐", style="white")
        
        # Content lines
        for line in lines:
            padding = width - len(line) - 4
            self.console.print(f"│ {line}{' ' * padding} │", style="white")
        
        # Bottom border
        self.console.print("└" + BOX_HORIZONTAL * (width - 2) + "┘", style="white")

    def scan_complete_animation(self, vuln_count: int) -> None:
        """
        Display scan completion with brief animation
        
        Args:
            vuln_count: Number of vulnerabilities found
        """
        completion_text = f"SCAN COMPLETE: {vuln_count} vulnerabilities detected"
        
        # Flash effect
        for _ in range(2):
            self.console.print(completion_text, style="white bold")
            time.sleep(0.15)
            self.console.clear()
            time.sleep(0.15)
        
        self.console.print(completion_text, style="white bold")
