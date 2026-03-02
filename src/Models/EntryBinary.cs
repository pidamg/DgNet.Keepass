namespace DgNet.Keepass;

public class EntryBinary {
	public string Name        { get; set; } = "";
	public byte[] Data        { get; set; } = [];
	public bool   IsProtected { get; set; }
}
