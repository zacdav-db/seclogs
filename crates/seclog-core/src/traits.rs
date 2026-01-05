use crate::event::Event;

/// Produces events one at a time for the generator loop.
pub trait EventSource {
    /// Returns the next event, or `None` if no event is available.
    fn next_event(&mut self) -> Option<Event>;
}

/// Writes events to a sink (files, streams, etc.).
pub trait EventWriter {
    /// Writes a single event and returns the number of bytes written.
    fn write_event(&mut self, event: &Event) -> std::io::Result<u64>;
    /// Flushes buffered data without closing the writer.
    fn flush(&mut self) -> std::io::Result<()>;
    /// Closes the writer, flushing any remaining data.
    fn close(&mut self) -> std::io::Result<()>;
}
