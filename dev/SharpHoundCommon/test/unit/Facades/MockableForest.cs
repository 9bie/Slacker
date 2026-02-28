using System.DirectoryServices.ActiveDirectory;

namespace CommonLibTest.Facades
{
    public class MockableForest
    {
        public static Forest Construct(string forestDnsName)
        {
            var forest = FacadeHelpers.GetUninitializedObject<Forest>();
            FacadeHelpers.SetProperty(forest, "_forestDnsName", forestDnsName);

            return forest;
        }
    }
}